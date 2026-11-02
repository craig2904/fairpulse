from core.fair_model import RiskScenario, TriangularRange, simulate_risk
from ui.charts import loss_distribution_figure, loss_exceedance_figure, percentile_comparison_figure, roi_bridge_figure


def test_plotly_charts_build_from_simulation_result():
    scenario = RiskScenario(
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
    result = simulate_risk(scenario, simulations=1_000, seed=42)
    assert len(loss_exceedance_figure(result).data) == 2
    assert len(loss_distribution_figure(result).data) == 2
    assert len(percentile_comparison_figure(result).data) == 2
    assert len(roi_bridge_figure(result).data) == 1
