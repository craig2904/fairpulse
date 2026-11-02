import numpy as np
import pytest

from core.fair_model import RiskScenario, TriangularRange, loss_exceedance_curve, simulate_risk


def sample_scenario() -> RiskScenario:
    return RiskScenario(
        cve_id="CVE-2024-3400",
        currency="USD",
        asset_value=6_300_000,
        threat_event_frequency=TriangularRange(1, 5, 12),
        base_susceptibility=TriangularRange(0.10, 0.25, 0.50),
        primary_loss=TriangularRange(20_000, 80_000, 250_000),
        secondary_loss=TriangularRange(0, 50_000, 500_000),
        current_control_maturity=35,
        target_control_maturity=85,
        maximum_effectiveness_at_full_maturity=0.70,
        mitigation_upfront_cost=125_000,
        mitigation_annual_cost=0,
        mitigation_life_years=5,
    )


def test_simulation_is_reproducible_for_same_seed():
    scenario = sample_scenario()
    a = simulate_risk(scenario, simulations=2_000, seed=123)
    b = simulate_risk(scenario, simulations=2_000, seed=123)
    assert a.current_ale == pytest.approx(b.current_ale)
    assert a.target_ale == pytest.approx(b.target_ale)
    np.testing.assert_array_equal(a.current_losses, b.current_losses)
    np.testing.assert_array_equal(a.target_losses, b.target_losses)


def test_higher_control_maturity_reduces_expected_annual_loss():
    result = simulate_risk(sample_scenario(), simulations=10_000, seed=42)
    assert result.current_ale > result.target_ale
    assert result.risk_reduction > 0


def test_annualised_cost_and_rosi_are_calculated_consistently():
    result = simulate_risk(sample_scenario(), simulations=1_000, seed=42)
    assert result.annualised_mitigation_cost == pytest.approx(25_000)
    assert result.rosi_percent == pytest.approx(
        ((result.risk_reduction - 25_000) / 25_000) * 100
    )


def test_zero_mitigation_cost_has_undefined_rosi_not_division_error():
    scenario = sample_scenario()
    scenario = RiskScenario(**{**scenario.__dict__, "mitigation_upfront_cost": 0, "mitigation_annual_cost": 0})
    result = simulate_risk(scenario, simulations=1_000, seed=42)
    assert result.rosi_percent is None


def test_validation_rejects_misordered_triangular_ranges():
    scenario = sample_scenario()
    scenario = RiskScenario(**{**scenario.__dict__, "threat_event_frequency": TriangularRange(5, 2, 12)})
    with pytest.raises(ValueError, match="low ≤ most likely ≤ high"):
        simulate_risk(scenario, simulations=1_000)


def test_loss_exceedance_curve_is_sorted_and_descending_probability():
    x, y = loss_exceedance_curve(np.array([30.0, 10.0, 20.0]))
    assert x.tolist() == [10.0, 20.0, 30.0]
    assert y.tolist() == pytest.approx([1.0, 2 / 3, 1 / 3])


def test_zero_width_triangular_ranges_are_supported():
    scenario = sample_scenario()
    scenario = RiskScenario(
        **{
            **scenario.__dict__,
            "threat_event_frequency": TriangularRange(2, 2, 2),
            "base_susceptibility": TriangularRange(0.2, 0.2, 0.2),
            "primary_loss": TriangularRange(10_000, 10_000, 10_000),
            "secondary_loss": TriangularRange(5_000, 5_000, 5_000),
        }
    )
    result = simulate_risk(scenario, simulations=1_000, seed=7)
    assert result.current_ale >= 0
    assert result.target_ale >= 0


def test_extreme_total_event_draws_fail_safely():
    scenario = sample_scenario()
    scenario = RiskScenario(
        **{
            **scenario.__dict__,
            "threat_event_frequency": TriangularRange(10_000, 10_000, 10_000),
            "base_susceptibility": TriangularRange(1, 1, 1),
            "current_control_maturity": 0,
            "target_control_maturity": 0,
            "maximum_effectiveness_at_full_maturity": 0,
        }
    )
    with pytest.raises(ValueError, match="5,000,000 event-severity draws"):
        simulate_risk(scenario, simulations=1_000, seed=1)


def test_ale_matches_the_modelled_compound_poisson_expectation_within_sampling_error():
    scenario = sample_scenario()
    result = simulate_risk(scenario, simulations=50_000, seed=100)
    mean_tef = sum((scenario.threat_event_frequency.low, scenario.threat_event_frequency.mode, scenario.threat_event_frequency.high)) / 3
    mean_sus = sum((scenario.base_susceptibility.low, scenario.base_susceptibility.mode, scenario.base_susceptibility.high)) / 3
    mean_loss = (
        sum((scenario.primary_loss.low, scenario.primary_loss.mode, scenario.primary_loss.high)) / 3
        + sum((scenario.secondary_loss.low, scenario.secondary_loss.mode, scenario.secondary_loss.high)) / 3
    )
    current_effectiveness = scenario.current_control_maturity / 100 * scenario.maximum_effectiveness_at_full_maturity
    expected_current_ale = mean_tef * mean_sus * (1 - current_effectiveness) * mean_loss
    assert result.current_ale == pytest.approx(expected_current_ale, rel=0.02)
