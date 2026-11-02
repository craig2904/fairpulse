"""FAIR-informed, transparent Monte Carlo cyber-risk model.

This is a portfolio-grade quantitative implementation, not a certified
implementation of every FAIR taxonomy or a substitute for a calibrated
enterprise risk model. It uses explicit analyst-provided distributions and
keeps the maturity-to-control-effectiveness mapping visible and configurable.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

import numpy as np


@dataclass(frozen=True)
class TriangularRange:
    """Low / most-likely / high values for a triangular distribution."""

    low: float
    mode: float
    high: float

    def validate(self, name: str, *, minimum: float | None = None, maximum: float | None = None) -> None:
        values = (self.low, self.mode, self.high)
        if not all(np.isfinite(v) for v in values):
            raise ValueError(f"{name}: all values must be finite numbers.")
        if not self.low <= self.mode <= self.high:
            raise ValueError(f"{name}: values must satisfy low ≤ most likely ≤ high.")
        if minimum is not None and self.low < minimum:
            raise ValueError(f"{name}: values cannot be below {minimum}.")
        if maximum is not None and self.high > maximum:
            raise ValueError(f"{name}: values cannot exceed {maximum}.")


@dataclass(frozen=True)
class RiskScenario:
    cve_id: str
    currency: str
    asset_value: float
    threat_event_frequency: TriangularRange  # events per year, before vulnerability
    base_susceptibility: TriangularRange  # probability (0–1) per threat event
    primary_loss: TriangularRange  # direct loss per loss event
    secondary_loss: TriangularRange  # indirect / secondary loss per loss event
    current_control_maturity: float  # 0–100, analyst assessment
    target_control_maturity: float  # 0–100, proposed state
    maximum_effectiveness_at_full_maturity: float  # 0–1, explicit calibration
    mitigation_upfront_cost: float
    mitigation_annual_cost: float
    mitigation_life_years: int

    def validate(self) -> None:
        if not self.cve_id.strip():
            raise ValueError("A CVE identifier is required.")
        if self.currency not in {"USD", "EUR", "GBP"}:
            raise ValueError("Currency must be USD, EUR or GBP.")
        if not np.isfinite(self.asset_value) or self.asset_value < 0:
            raise ValueError("Asset value must be a finite non-negative number.")
        self.threat_event_frequency.validate("Threat event frequency", minimum=0, maximum=10_000)
        self.base_susceptibility.validate("Base susceptibility", minimum=0, maximum=1)
        self.primary_loss.validate("Primary loss", minimum=0)
        self.secondary_loss.validate("Secondary loss", minimum=0)
        for label, value in (
            ("Current control maturity", self.current_control_maturity),
            ("Target control maturity", self.target_control_maturity),
            ("Maximum effectiveness at full maturity", self.maximum_effectiveness_at_full_maturity),
        ):
            if not np.isfinite(value):
                raise ValueError(f"{label} must be finite.")
        if not 0 <= self.current_control_maturity <= 100:
            raise ValueError("Current control maturity must be between 0 and 100.")
        if not 0 <= self.target_control_maturity <= 100:
            raise ValueError("Target control maturity must be between 0 and 100.")
        if not 0 <= self.maximum_effectiveness_at_full_maturity <= 1:
            raise ValueError("Maximum effectiveness must be between 0 and 1.")
        if not np.isfinite(self.mitigation_upfront_cost) or not np.isfinite(self.mitigation_annual_cost):
            raise ValueError("Mitigation costs must be finite numbers.")
        if self.mitigation_upfront_cost < 0 or self.mitigation_annual_cost < 0:
            raise ValueError("Mitigation costs cannot be negative.")
        if int(self.mitigation_life_years) != self.mitigation_life_years or not 1 <= int(self.mitigation_life_years) <= 30:
            raise ValueError("Mitigation useful life must be a whole number between 1 and 30 years.")

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "currency": self.currency,
            "asset_value": self.asset_value,
            "threat_event_frequency": asdict(self.threat_event_frequency),
            "base_susceptibility": asdict(self.base_susceptibility),
            "primary_loss": asdict(self.primary_loss),
            "secondary_loss": asdict(self.secondary_loss),
            "current_control_maturity": self.current_control_maturity,
            "target_control_maturity": self.target_control_maturity,
            "maximum_effectiveness_at_full_maturity": self.maximum_effectiveness_at_full_maturity,
            "mitigation_upfront_cost": self.mitigation_upfront_cost,
            "mitigation_annual_cost": self.mitigation_annual_cost,
            "mitigation_life_years": self.mitigation_life_years,
        }


@dataclass
class SimulationResult:
    scenario: RiskScenario
    simulations: int
    seed: int
    current_losses: np.ndarray
    target_losses: np.ndarray
    current_ale: float
    target_ale: float
    risk_reduction: float
    annualised_mitigation_cost: float
    net_annual_benefit: float
    rosi_percent: float | None
    payback_years: float | None
    current_percentiles: dict[str, float]
    target_percentiles: dict[str, float]
    current_zero_loss_probability: float
    target_zero_loss_probability: float
    current_control_effectiveness: float
    target_control_effectiveness: float


def _sample_triangular(rng: np.random.Generator, limits: TriangularRange, size: int) -> np.ndarray:
    # NumPy requires a non-zero interval for triangular(); a zero-width range
    # is a legitimate analyst input and represents a deterministic value.
    if limits.low == limits.high:
        return np.full(size, limits.low, dtype=np.float64)
    return rng.triangular(limits.low, limits.mode, limits.high, size=size)


def _compound_poisson_annual_losses(
    rng: np.random.Generator,
    annual_loss_event_rates: np.ndarray,
    primary: TriangularRange,
    secondary: TriangularRange,
    *,
    chunk_size: int = 256,
) -> np.ndarray:
    """Generate aggregate annual losses using a compound Poisson process.

    Chunking bounds temporary memory even when an analyst enters a high event
    frequency. Each successful loss event receives independently sampled
    primary and secondary severity.
    """

    if np.any(~np.isfinite(annual_loss_event_rates)) or np.any(annual_loss_event_rates < 0):
        raise ValueError("Annual loss-event rates must be finite and non-negative.")

    event_counts = rng.poisson(annual_loss_event_rates)
    total_event_draws = int(event_counts.sum())
    if total_event_draws > 5_000_000:
        raise ValueError(
            "This scenario implies more than 5,000,000 event-severity draws per state. "
            "Reduce the upper threat-event-frequency assumption or the simulation count."
        )
    annual_losses = np.zeros(event_counts.size, dtype=np.float64)

    for start in range(0, event_counts.size, chunk_size):
        end = min(start + chunk_size, event_counts.size)
        chunk_counts = event_counts[start:end]
        event_rows = np.repeat(np.arange(chunk_counts.size), chunk_counts)
        if event_rows.size == 0:
            continue

        primary_losses = _sample_triangular(rng, primary, event_rows.size)
        secondary_losses = _sample_triangular(rng, secondary, event_rows.size)
        event_severity = primary_losses + secondary_losses
        annual_losses[start:end] = np.bincount(
            event_rows,
            weights=event_severity,
            minlength=chunk_counts.size,
        )

    return annual_losses


def _percentiles(losses: np.ndarray) -> dict[str, float]:
    values = np.percentile(losses, [50, 75, 90, 95, 99])
    return {
        "p50": float(values[0]),
        "p75": float(values[1]),
        "p90": float(values[2]),
        "p95": float(values[3]),
        "p99": float(values[4]),
    }


def simulate_risk(
    scenario: RiskScenario,
    *,
    simulations: int = 10_000,
    seed: int = 42,
) -> SimulationResult:
    """Run current-state and target-state Monte Carlo simulations.

    Model structure:
      Loss Event Frequency = Threat Event Frequency × Vulnerability
      Vulnerability proxy = base susceptibility × (1 - control effectiveness)
      Annual aggregate loss = compound Poisson count × sampled event severity

    The maturity-to-effectiveness conversion is an explicit analyst-selected
    linear calibration, not a FAIR-prescribed conversion:
      control effectiveness = maturity × max_effectiveness_at_full_maturity

    EPSS and KEV are deliberately not substituted for organisation-specific
    TEF or susceptibility. They are contextual threat evidence shown in the UI.
    """

    scenario.validate()
    if not isinstance(simulations, int) or not 100 <= simulations <= 100_000:
        raise ValueError("Simulation count must be an integer between 100 and 100,000.")
    if not isinstance(seed, int) or seed < 0:
        raise ValueError("Random seed must be a non-negative integer.")

    rng = np.random.default_rng(seed)

    # Common uncertainty draws are used for both states to make the comparison
    # less sensitive to unrelated differences in sampled threat assumptions.
    tef = _sample_triangular(rng, scenario.threat_event_frequency, simulations)
    susceptibility = _sample_triangular(rng, scenario.base_susceptibility, simulations)

    current_effectiveness = (
        scenario.current_control_maturity / 100.0
    ) * scenario.maximum_effectiveness_at_full_maturity
    target_effectiveness = (
        scenario.target_control_maturity / 100.0
    ) * scenario.maximum_effectiveness_at_full_maturity

    current_vulnerability = susceptibility * (1.0 - current_effectiveness)
    target_vulnerability = susceptibility * (1.0 - target_effectiveness)

    current_rates = tef * current_vulnerability
    target_rates = tef * target_vulnerability

    current_losses = _compound_poisson_annual_losses(
        rng, current_rates, scenario.primary_loss, scenario.secondary_loss
    )
    target_losses = _compound_poisson_annual_losses(
        rng, target_rates, scenario.primary_loss, scenario.secondary_loss
    )

    current_ale = float(np.mean(current_losses))
    target_ale = float(np.mean(target_losses))
    risk_reduction = current_ale - target_ale
    annualised_cost = (
        scenario.mitigation_upfront_cost / scenario.mitigation_life_years
    ) + scenario.mitigation_annual_cost
    net_annual_benefit = risk_reduction - annualised_cost
    rosi = (
        (net_annual_benefit / annualised_cost) * 100.0
        if annualised_cost > 0
        else None
    )

    net_of_recurring_cost = risk_reduction - scenario.mitigation_annual_cost
    if scenario.mitigation_upfront_cost == 0:
        payback = 0.0 if net_of_recurring_cost > 0 else None
    elif net_of_recurring_cost > 0:
        payback = scenario.mitigation_upfront_cost / net_of_recurring_cost
    else:
        payback = None

    return SimulationResult(
        scenario=scenario,
        simulations=simulations,
        seed=seed,
        current_losses=current_losses,
        target_losses=target_losses,
        current_ale=current_ale,
        target_ale=target_ale,
        risk_reduction=risk_reduction,
        annualised_mitigation_cost=float(annualised_cost),
        net_annual_benefit=float(net_annual_benefit),
        rosi_percent=float(rosi) if rosi is not None else None,
        payback_years=float(payback) if payback is not None else None,
        current_percentiles=_percentiles(current_losses),
        target_percentiles=_percentiles(target_losses),
        current_zero_loss_probability=float(np.mean(current_losses == 0)),
        target_zero_loss_probability=float(np.mean(target_losses == 0)),
        current_control_effectiveness=float(current_effectiveness),
        target_control_effectiveness=float(target_effectiveness),
    )


def loss_exceedance_curve(losses: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Return ascending loss values and empirical P(annual loss >= x)."""

    values = np.asarray(losses, dtype=np.float64)
    if values.ndim != 1 or values.size == 0 or np.any(~np.isfinite(values)):
        raise ValueError("Losses must be a non-empty one-dimensional finite array.")
    sorted_losses = np.sort(values)
    exceedance_probability = (values.size - np.arange(values.size)) / values.size
    return sorted_losses, exceedance_probability
