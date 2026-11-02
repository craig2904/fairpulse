from __future__ import annotations

import csv
import io
import json
import os
from datetime import datetime, timezone
from typing import Any

import streamlit as st

from core.fair_model import RiskScenario, SimulationResult, TriangularRange, simulate_risk
from governance.crosswalk import all_mappings
from integrations.threat_intel import (
    ThreatIntelError,
    fetch_epss,
    fetch_kev_catalog,
    lookup_kev,
    validate_cve_id,
)
from ui.charts import (
    loss_distribution_figure,
    loss_exceedance_figure,
    percentile_comparison_figure,
    roi_bridge_figure,
)


# ---------------------------------------------------------------------------
# Page configuration and design system
# ---------------------------------------------------------------------------
st.set_page_config(
    page_title="FairPulse | Cyber Risk Quantification",
    page_icon="◈",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
      @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700;800&display=swap');
      :root {
        --fp-bg: #000000;
        --fp-surface: #0A0E17;
        --fp-surface-2: #101827;
        --fp-border: #253247;
        --fp-cyan: #00E5FF;
        --fp-green: #10B981;
        --fp-red: #EF4444;
        --fp-text: #F5F7FA;
        --fp-muted: #9AA6B6;
      }
      html, body, [class*="css"], [data-testid="stAppViewContainer"] {
        font-family: 'Outfit', Inter, 'Segoe UI', sans-serif;
      }
      .stApp { background: radial-gradient(ellipse at 75% -10%, rgba(0,229,255,.12), transparent 38%), #000; color: var(--fp-text); }
      [data-testid="stHeader"] { background: rgba(0,0,0,.76); }
      [data-testid="stSidebar"] { background: linear-gradient(180deg, #0A0E17 0%, #070A11 100%); border-right: 1px solid var(--fp-border); }
      [data-testid="stSidebar"] > div:first-child { padding-top: 1.2rem; }
      [data-testid="stSidebar"] label, [data-testid="stSidebar"] p { color: #C4CDD8; }
      h1, h2, h3 { letter-spacing: -0.035em; }
      h1 { font-weight: 800 !important; }
      h2, h3 { font-weight: 650 !important; }
      p, li { color: #C2CBD7; }
      [data-testid="stMetric"] { background: linear-gradient(145deg, rgba(16,24,39,.96), rgba(10,14,23,.96)); border: 1px solid var(--fp-border); padding: 16px 18px; border-radius: 16px; }
      [data-testid="stMetricLabel"] { color: var(--fp-muted) !important; font-size: .78rem !important; }
      [data-testid="stMetricValue"] { color: var(--fp-text) !important; font-weight: 750 !important; letter-spacing: -.04em; }
      [data-testid="stMetricDelta"] { font-size: .8rem !important; }
      .fp-hero { border: 1px solid rgba(0,229,255,.23); border-radius: 22px; padding: 30px 32px; background: radial-gradient(ellipse at 88% 0%, rgba(0,229,255,.14), transparent 43%), linear-gradient(135deg, #0A0E17 0%, #05070D 75%); box-shadow: 0 18px 60px rgba(0,0,0,.30); margin: 4px 0 20px 0; }
      .fp-kicker { color: var(--fp-cyan); font-size: .72rem; font-weight: 700; letter-spacing: .16em; text-transform: uppercase; }
      .fp-hero-title { color: #F5F7FA; font-size: clamp(2rem, 4vw, 3.35rem); line-height: 1.04; font-weight: 800; letter-spacing: -.055em; margin: 10px 0 12px 0; }
      .fp-hero-copy { color: #AAB6C5; font-size: 1.02rem; max-width: 850px; line-height: 1.6; }
      .fp-pills { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 18px; }
      .fp-pill { color: #DDE7F2; background: rgba(255,255,255,.035); border: 1px solid #253247; padding: 6px 10px; border-radius: 999px; font-size: .74rem; }
      .fp-panel { border: 1px solid var(--fp-border); border-radius: 16px; background: linear-gradient(145deg, rgba(16,24,39,.88), rgba(7,10,17,.96)); padding: 18px 20px; margin: 8px 0 14px 0; }
      .fp-panel-title { color: var(--fp-text); font-size: 1.04rem; font-weight: 700; margin-bottom: 6px; }
      .fp-muted { color: var(--fp-muted); font-size: .86rem; }
      .fp-status { display: inline-flex; align-items: center; gap: 8px; color: #DCE5EF; font-size: .85rem; }
      .fp-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; }
      .fp-dot-green { background: var(--fp-green); box-shadow: 0 0 12px rgba(16,185,129,.55); }
      .fp-dot-red { background: var(--fp-red); }
      .fp-dot-cyan { background: var(--fp-cyan); }
      .fp-callout { border-left: 3px solid var(--fp-cyan); padding: 10px 14px; background: rgba(0,229,255,.055); border-radius: 0 10px 10px 0; color: #DCE6F0; margin: 10px 0; }
      .fp-warning { border-left-color: #F59E0B; background: rgba(245,158,11,.07); }
      .fp-divider { border-top: 1px solid var(--fp-border); margin: 18px 0; }
      .fp-small { color: var(--fp-muted); font-size: .76rem; }
      .fp-big { color: #F5F7FA; font-size: 1.75rem; font-weight: 800; letter-spacing: -.04em; }
      /* Consistent, high-contrast controls across Streamlit versions. */
      .stButton > button, .stLinkButton > a,
      [data-testid="stFormSubmitButton"] > button,
      [data-testid="stDownloadButton"] > button {
        border-radius: 10px !important;
        font-weight: 700 !important;
        min-height: 44px !important;
        line-height: 1.25 !important;
        white-space: normal !important;
        opacity: 1 !important;
        text-shadow: none !important;
      }
      [data-testid="stFormSubmitButton"] > button,
      .stButton > button[kind="primary"] {
        background: #00E5FF !important;
        border: 1px solid #00E5FF !important;
        color: #001014 !important;
      }
      [data-testid="stFormSubmitButton"] > button p,
      .stButton > button[kind="primary"] p,
      [data-testid="stDownloadButton"] > button p { color: inherit !important; }
      .stButton > button[kind="secondary"], .stLinkButton > a,
      [data-testid="stDownloadButton"] > button {
        border: 1px solid #345064 !important;
        background: #101827 !important;
        color: #F5F7FA !important;
      }
      .stButton > button:focus, .stLinkButton > a:focus,
      [data-testid="stFormSubmitButton"] > button:focus,
      [data-testid="stDownloadButton"] > button:focus {
        outline: 2px solid #00E5FF !important;
        outline-offset: 2px !important;
      }
      .stTabs [data-baseweb="tab-list"] { gap: 7px; border-bottom: 1px solid var(--fp-border); }
      .stTabs [data-baseweb="tab"] { min-height: 46px; background: transparent; border-radius: 10px 10px 0 0; color: #AAB6C5; padding: 0 16px; }
      .stTabs [aria-selected="true"] { color: var(--fp-cyan) !important; border-bottom: 2px solid var(--fp-cyan) !important; }
      [data-testid="stExpander"] { border: 1px solid var(--fp-border); border-radius: 12px; background: rgba(10,14,23,.48); }
      [data-testid="stDataFrame"] { border: 1px solid var(--fp-border); border-radius: 12px; overflow: hidden; }
      [data-testid="stAlert"] { border-radius: 12px; }
      .stTextInput input, .stNumberInput input, .stSelectbox [data-baseweb="select"] > div { border-radius: 9px !important; }
      footer { visibility: hidden; }
      @media (max-width: 760px) {
        .fp-hero { padding: 22px 18px; border-radius: 16px; }
        .fp-hero-copy { font-size: .93rem; }
        .stTabs [data-baseweb="tab-list"] { overflow-x: auto; flex-wrap: nowrap; }
        .stTabs [data-baseweb="tab"] { white-space: nowrap; padding: 0 10px; font-size: .82rem; }
        [data-testid="stMetric"] { padding: 12px 13px; }
        [data-testid="stMetricValue"] { font-size: 1.35rem !important; }
      }
    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------------------------
# Configuration, formatting and reusable UI helpers
# ---------------------------------------------------------------------------
def get_link_setting(key: str) -> str:
    """Read a profile link from environment/secrets, falling back to project defaults."""
    defaults = {
        "github_url": "https://github.com/craig2904/fairpulse",
        "linkedin_url": "https://www.linkedin.com/in/craig-c-manohar-863b252b5/",
    }
    env_name = f"FAIRPULSE_{key.upper()}_URL"
    env_value = os.getenv(env_name, "").strip()
    if env_value:
        return env_value
    try:
        links = st.secrets.get("links", {})
        value = links.get(key, "") if hasattr(links, "get") else ""
        configured_value = str(value).strip()
        if configured_value and "YOUR_" not in configured_value:
            return configured_value
    except Exception:
        pass
    return defaults.get(key, "")


def currency_symbol(currency: str) -> str:
    return {"USD": "$", "EUR": "€", "GBP": "£"}.get(currency, currency + " ")


def money(value: float | None, currency: str, decimals: int = 0) -> str:
    if value is None:
        return "N/A"
    symbol = currency_symbol(currency)
    number = f"{value:,.{decimals}f}"
    if abs(value) >= 1_000_000:
        return f"{symbol}{value / 1_000_000:,.2f}M"
    if abs(value) >= 10_000:
        return f"{symbol}{value / 1_000:,.1f}K"
    return f"{symbol}{number}"


def percent(value: float | None, decimals: int = 1) -> str:
    return "N/A" if value is None else f"{value * 100:.{decimals}f}%"




def make_ciso_summary(result: SimulationResult, intel: dict[str, Any] | None) -> str:
    currency = result.scenario.currency
    s = result.scenario
    lines = [
        f"FairPulse completed a {result.simulations:,}-iteration Monte Carlo analysis for {s.cve_id}.",
        f"The modelled current-state Annualized Loss Expectancy (ALE) is {money(result.current_ale, currency)}; the proposed-state ALE is {money(result.target_ale, currency)}.",
        f"The estimated annual risk reduction is {money(result.risk_reduction, currency)}. The mitigation's straight-line annualised cost is {money(result.annualised_mitigation_cost, currency)}.",
    ]
    if result.rosi_percent is None:
        lines.append("ROSI is not defined because the annualised mitigation cost is zero; the modelled risk reduction is shown separately.")
    else:
        lines.append(f"The modelled net ROSI is {result.rosi_percent:,.1f}% after annualised mitigation cost; net annual benefit is {money(result.net_annual_benefit, currency)}.")
    if result.payback_years is not None:
        lines.append(f"Simple payback on upfront cost, after recurring mitigation cost, is approximately {result.payback_years:,.2f} years.")
    else:
        lines.append("A simple payback period is not demonstrated under the entered assumptions.")

    if intel:
        epss = intel.get("epss")
        kev = intel.get("kev")
        if epss and not intel.get("epss_error"):
            lines.append(f"FIRST EPSS reports {epss['epss'] * 100:.2f}% estimated exploitation probability over the next 30 days (dataset date: {epss.get('date') or 'not supplied'}).")
        if kev and not intel.get("kev_error"):
            if kev.get("listed"):
                lines.append("CISA KEV includes this CVE. Confirm affected product/version and remediation applicability as a priority.")
            else:
                lines.append("This CVE was not found in the retrieved CISA KEV catalogue; absence from KEV is not proof of safety.")

    lines.extend([
        "Recommended management actions: validate the affected asset and exposure; confirm the vendor's remediation or compensating control; assign an accountable owner and due date; and revisit the loss assumptions with business, legal and operational stakeholders.",
        "The results are conditional estimates based on analyst-entered distributions and the disclosed control-maturity calibration. They are not a forecast, legal opinion or guarantee of loss.",
    ])
    return "\n\n".join(lines)


def result_to_payload(result: SimulationResult, intel: dict[str, Any] | None) -> dict[str, Any]:
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "model": "FairPulse FAIR-informed Monte Carlo model",
        "model_version": "1.0.0",
        "simulations": result.simulations,
        "seed": result.seed,
        "scenario": result.scenario.to_dict(),
        "threat_intelligence": intel or {},
        "results": {
            "current_ale": result.current_ale,
            "target_ale": result.target_ale,
            "risk_reduction": result.risk_reduction,
            "annualised_mitigation_cost": result.annualised_mitigation_cost,
            "net_annual_benefit": result.net_annual_benefit,
            "rosi_percent": result.rosi_percent,
            "payback_years": result.payback_years,
            "current_percentiles": result.current_percentiles,
            "target_percentiles": result.target_percentiles,
            "current_zero_loss_probability": result.current_zero_loss_probability,
            "target_zero_loss_probability": result.target_zero_loss_probability,
            "current_control_effectiveness": result.current_control_effectiveness,
            "target_control_effectiveness": result.target_control_effectiveness,
        },
        "methodology_notes": [
            "Loss Event Frequency is modelled as annual threat event frequency multiplied by susceptibility.",
            "Susceptibility is reduced by an explicit linear control-maturity-to-effectiveness calibration.",
            "Annual aggregate loss uses a compound Poisson event count and triangular primary/secondary loss distributions.",
            "EPSS and KEV are context only; the analyst must translate intelligence into organisation-specific assumptions.",
            "Asset value is an exposure reference and is not automatically treated as the loss magnitude or a hard cap.",
        ],
    }


def result_to_csv(result: SimulationResult) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["metric", "current_state", "proposed_state", "currency"])
    writer.writerow(["ALE", result.current_ale, result.target_ale, result.scenario.currency])
    writer.writerow(["P50 annual loss", result.current_percentiles["p50"], result.target_percentiles["p50"], result.scenario.currency])
    writer.writerow(["P90 annual loss", result.current_percentiles["p90"], result.target_percentiles["p90"], result.scenario.currency])
    writer.writerow(["P95 annual loss", result.current_percentiles["p95"], result.target_percentiles["p95"], result.scenario.currency])
    writer.writerow(["P99 annual loss", result.current_percentiles["p99"], result.target_percentiles["p99"], result.scenario.currency])
    writer.writerow(["Zero-loss probability", result.current_zero_loss_probability, result.target_zero_loss_probability, "probability"])
    writer.writerow(["Risk reduction", result.risk_reduction, "", result.scenario.currency])
    writer.writerow(["Annualised mitigation cost", result.annualised_mitigation_cost, "", result.scenario.currency])
    writer.writerow(["Net annual benefit", result.net_annual_benefit, "", result.scenario.currency])
    writer.writerow(["ROSI percent", result.rosi_percent if result.rosi_percent is not None else "N/A", "", "percent"])
    return output.getvalue().encode("utf-8")


# Cached public data: EPSS score per CVE and the public CISA KEV catalogue.
@st.cache_data(ttl=3600, show_spinner=False)
def cached_epss(cve_id: str) -> dict[str, Any] | None:
    return fetch_epss(cve_id)


@st.cache_data(ttl=3600, show_spinner=False)
def cached_kev_catalog() -> dict[str, Any]:
    return fetch_kev_catalog()


def build_scenario_from_form(values: dict[str, Any]) -> RiskScenario:
    return RiskScenario(
        cve_id=validate_cve_id(values["cve_id"]),
        currency=values["currency"],
        asset_value=float(values["asset_value"]),
        threat_event_frequency=TriangularRange(float(values["tef_low"]), float(values["tef_mode"]), float(values["tef_high"])),
        base_susceptibility=TriangularRange(float(values["sus_low"]), float(values["sus_mode"]), float(values["sus_high"])),
        primary_loss=TriangularRange(float(values["primary_low"]), float(values["primary_mode"]), float(values["primary_high"])),
        secondary_loss=TriangularRange(float(values["secondary_low"]), float(values["secondary_mode"]), float(values["secondary_high"])),
        current_control_maturity=float(values["current_maturity"]),
        target_control_maturity=float(values["target_maturity"]),
        maximum_effectiveness_at_full_maturity=float(values["max_effectiveness"]) / 100.0,
        mitigation_upfront_cost=float(values["upfront_cost"]),
        mitigation_annual_cost=float(values["annual_cost"]),
        mitigation_life_years=int(values["life_years"]),
    )


# ---------------------------------------------------------------------------
# Header and scenario input form
# ---------------------------------------------------------------------------
github_url = get_link_setting("github_url")
linkedin_url = get_link_setting("linkedin_url")

header_left, header_right = st.columns([5, 2])
with header_left:
    st.markdown(
        '<div style="display:flex;align-items:center;gap:12px;margin:4px 0 8px 0">'
        '<div style="width:40px;height:40px;border:1px solid rgba(0,229,255,.45);border-radius:12px;display:flex;align-items:center;justify-content:center;color:#00E5FF;font-size:24px;background:rgba(0,229,255,.06)">◈</div>'
        '<div><div style="font-size:1.2rem;font-weight:800;letter-spacing:-.04em;color:#F5F7FA">FAIRPULSE</div>'
        '<div style="font-size:.69rem;letter-spacing:.13em;color:#8D9AAA;text-transform:uppercase">Cyber Risk Quantification</div></div></div>',
        unsafe_allow_html=True,
    )
with header_right:
    link_cols = st.columns(2)
    with link_cols[0]:
        if github_url:
            st.link_button("View Source Code", github_url, use_container_width=True)
        else:
            st.button("GitHub URL not set", disabled=True, use_container_width=True)
    with link_cols[1]:
        if linkedin_url:
            st.link_button("LinkedIn", linkedin_url, use_container_width=True)
        else:
            st.button("LinkedIn not set", disabled=True, use_container_width=True)

st.markdown(
    '<div class="fp-hero">'
    '<div class="fp-kicker">FAIR-INFORMED · MONTE CARLO · FINANCIAL RISK</div>'
    '<div class="fp-hero-title">Turn cyber threats into<br>financial decisions.</div>'
    '<div class="fp-hero-copy">Translate vulnerability and threat-intelligence evidence into transparent estimates of annual financial loss. Compare current controls with a proposed mitigation and inspect the assumptions behind every result.</div>'
    '<div class="fp-pills"><span class="fp-pill">FIRST.org EPSS</span><span class="fp-pill">CISA KEV</span><span class="fp-pill">10,000 simulations by default</span><span class="fp-pill">DORA · NIS2 · ISO 27001 crosswalk</span></div>'
    '</div>',
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown("## Scenario parameters")
    st.caption("Set the assumptions, then submit once. Calculations do not run on every slider change.")
    st.caption("Default scenario values are illustrative placeholders. Replace them with evidence-backed estimates.")
    with st.form("fairpulse_scenario_form", clear_on_submit=False):
        cve_id = st.text_input("Vulnerability (CVE)", value="CVE-2024-3400", help="Example identifier only. The application verifies the format and looks it up in FIRST EPSS and CISA KEV.")
        currency = st.selectbox("Reporting currency", ["USD", "EUR", "GBP"], index=0)
        st.caption("All financial inputs and outputs use this unit; no FX conversion is performed.")
        asset_value = st.number_input("Business asset value", min_value=0.0, value=6_300_000.0, step=100_000.0, help="Contextual exposure reference. It is not automatically used as loss magnitude or a loss cap.")

        with st.expander("Threat-event assumptions", expanded=True):
            st.caption("Analyst-entered ranges. EPSS and KEV inform judgement but are not direct substitutes for organisation-specific frequency.")
            t1, t2, t3 = st.columns(3)
            tef_low = t1.number_input("TEF low / yr", min_value=0.0, value=1.0, step=1.0, key="tef_low")
            tef_mode = t2.number_input("Most likely", min_value=0.0, value=5.0, step=1.0, key="tef_mode")
            tef_high = t3.number_input("TEF high", min_value=0.0, value=12.0, step=1.0, key="tef_high")
            s1, s2, s3 = st.columns(3)
            sus_low = s1.number_input("Sus. low %", min_value=0.0, max_value=100.0, value=10.0, step=1.0, key="sus_low") / 100.0
            sus_mode = s2.number_input("Most likely", min_value=0.0, max_value=100.0, value=25.0, step=1.0, key="sus_mode") / 100.0
            sus_high = s3.number_input("Sus. high %", min_value=0.0, max_value=100.0, value=50.0, step=1.0, key="sus_high") / 100.0

        with st.expander("Loss magnitude assumptions", expanded=False):
            st.caption("Per successful loss event. Primary = direct response / recovery / interruption; secondary = indirect / legal / customer impacts.")
            st.markdown("**Primary loss**")
            p1, p2, p3 = st.columns(3)
            primary_low = p1.number_input("Low", min_value=0.0, value=20_000.0, step=5_000.0, key="primary_low")
            primary_mode = p2.number_input("Likely", min_value=0.0, value=80_000.0, step=5_000.0, key="primary_mode")
            primary_high = p3.number_input("High", min_value=0.0, value=250_000.0, step=10_000.0, key="primary_high")
            st.markdown("**Secondary loss**")
            q1, q2, q3 = st.columns(3)
            secondary_low = q1.number_input("Low", min_value=0.0, value=0.0, step=5_000.0, key="secondary_low")
            secondary_mode = q2.number_input("Likely", min_value=0.0, value=50_000.0, step=5_000.0, key="secondary_mode")
            secondary_high = q3.number_input("High", min_value=0.0, value=500_000.0, step=10_000.0, key="secondary_high")

        with st.expander("Control and mitigation", expanded=True):
            current_maturity = st.slider("Current control maturity", min_value=0, max_value=100, value=35, step=5, help="Analyst-assessed maturity score; not a direct measurement of control effectiveness.")
            target_maturity = st.slider("Proposed control maturity", min_value=0, max_value=100, value=85, step=5)
            max_effectiveness = st.slider("Effectiveness at 100% maturity", min_value=0, max_value=100, value=70, step=5, help="Explicit calibration assumption used to translate maturity into a susceptibility reduction.")
            upfront_cost = st.number_input("One-off mitigation cost", min_value=0.0, value=125_000.0, step=5_000.0)
            annual_cost = st.number_input("Annual operating cost", min_value=0.0, value=0.0, step=1_000.0)
            life_years = st.number_input("Useful life (years)", min_value=1, max_value=30, value=5, step=1)

        with st.expander("Simulation settings", expanded=False):
            simulation_count = st.selectbox("Iterations", [1_000, 5_000, 10_000, 25_000, 50_000], index=2)
            seed = st.number_input("Random seed", min_value=0, max_value=2_147_483_647, value=42, step=1)

        submitted = st.form_submit_button("Run Monte Carlo Simulation", type="primary", use_container_width=True)

    if st.button("↻ Refresh threat intelligence cache", use_container_width=True):
        cached_epss.clear()
        cached_kev_catalog.clear()
        st.rerun()

    st.markdown("---")
    st.caption("No account, database or external storage is configured. Scenario inputs and results remain in this Streamlit session.")


# ---------------------------------------------------------------------------
# Execute the submitted scenario
# ---------------------------------------------------------------------------
if "fairpulse_result" not in st.session_state:
    st.session_state.fairpulse_result = None
if "fairpulse_intel" not in st.session_state:
    st.session_state.fairpulse_intel = None
if "fairpulse_run_at" not in st.session_state:
    st.session_state.fairpulse_run_at = None
if "fairpulse_error" not in st.session_state:
    st.session_state.fairpulse_error = None

if submitted:
    st.session_state.fairpulse_result = None
    st.session_state.fairpulse_intel = None
    st.session_state.fairpulse_error = None
    try:
        form_values = {
            "cve_id": cve_id,
            "currency": currency,
            "asset_value": asset_value,
            "tef_low": tef_low,
            "tef_mode": tef_mode,
            "tef_high": tef_high,
            "sus_low": sus_low,
            "sus_mode": sus_mode,
            "sus_high": sus_high,
            "primary_low": primary_low,
            "primary_mode": primary_mode,
            "primary_high": primary_high,
            "secondary_low": secondary_low,
            "secondary_mode": secondary_mode,
            "secondary_high": secondary_high,
            "current_maturity": current_maturity,
            "target_maturity": target_maturity,
            "max_effectiveness": max_effectiveness,
            "upfront_cost": upfront_cost,
            "annual_cost": annual_cost,
            "life_years": life_years,
        }
        scenario = build_scenario_from_form(form_values)
        scenario.validate()

        intel: dict[str, Any] = {"epss": None, "kev": None}
        try:
            intel["epss"] = cached_epss(scenario.cve_id)
        except (ThreatIntelError, ValueError) as exc:
            intel["epss_error"] = str(exc)
        try:
            catalog = cached_kev_catalog()
            intel["kev"] = lookup_kev(scenario.cve_id, catalog)
        except (ThreatIntelError, ValueError) as exc:
            intel["kev_error"] = str(exc)

        with st.spinner("Running Monte Carlo model and preparing financial outputs..."):
            result = simulate_risk(scenario, simulations=int(simulation_count), seed=int(seed))
        st.session_state.fairpulse_result = result
        st.session_state.fairpulse_intel = intel
        st.session_state.fairpulse_run_at = datetime.now(timezone.utc).isoformat()
    except (ValueError, TypeError) as exc:
        st.session_state.fairpulse_error = str(exc)
    except Exception as exc:  # keep the UI operational while exposing a useful error
        st.session_state.fairpulse_error = f"The scenario could not be completed: {exc}"

if st.session_state.fairpulse_error:
    st.error(st.session_state.fairpulse_error)

result: SimulationResult | None = st.session_state.fairpulse_result
intel: dict[str, Any] | None = st.session_state.fairpulse_intel

if result:
    run_time = st.session_state.fairpulse_run_at or ""
    st.caption(f"Last completed scenario: {result.scenario.cve_id} · {result.simulations:,} iterations · Seed {result.seed} · {run_time}")
else:
    st.caption("No scenario has been run in this session. The defaults are illustrative inputs, not live risk findings.")

# ---------------------------------------------------------------------------
# Four-view application navigation
# ---------------------------------------------------------------------------
overview_tab, lec_tab, roi_tab, governance_tab = st.tabs([
    "01  Risk Overview",
    "02  Loss Distribution",
    "03  Mitigation ROI",
    "04  Governance",
])

with overview_tab:
    st.markdown("## Executive risk overview")
    st.markdown("A financial view of the selected vulnerability scenario, with the model assumptions kept visible.")
    if result:
        c = result.scenario.currency
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Current ALE", money(result.current_ale, c), help="Mean simulated annual aggregate loss in the current control state.")
        m2.metric("Target ALE", money(result.target_ale, c), help="Mean simulated annual aggregate loss under the proposed control assumptions.")
        m3.metric("Modelled risk reduction", money(result.risk_reduction, c), delta=f"{(result.risk_reduction / result.current_ale * 100):.1f}% of current ALE" if result.current_ale > 0 else None)
        m4.metric("Net ROSI", f"{result.rosi_percent:,.1f}%" if result.rosi_percent is not None else "N/A", delta=money(result.net_annual_benefit, c) + " net / year" if result.rosi_percent is not None else "Annualised cost is zero")
        if result.scenario.asset_value > 0:
            p95_ratio = result.current_percentiles["p95"] / result.scenario.asset_value
            st.caption(f"Asset-value reference: {money(result.scenario.asset_value, c)} · Current-state P95 annual loss is {p95_ratio:.1%} of that reference. Asset value is contextual and is not used as a loss cap.")
        else:
            st.caption("Asset-value reference not supplied; loss estimates remain based on the entered loss-magnitude ranges.")

        left, right = st.columns([1.25, 1])
        with left:
            st.plotly_chart(loss_exceedance_figure(result), use_container_width=True, key="overview_loss_exceedance", config={"displaylogo": False, "responsive": True})
        with right:
            st.markdown("### Live threat intelligence")
            epss = intel.get("epss") if intel else None
            kev = intel.get("kev") if intel else None
            if epss and not (intel or {}).get("epss_error"):
                st.metric("EPSS · next 30 days", f"{epss['epss'] * 100:.2f}%", help="FIRST estimate for exploitation of this vulnerability in the next 30 days.")
                st.caption(f"Percentile {epss['percentile'] * 100:.2f}% · Dataset date {epss.get('date') or 'not supplied'}")
            elif intel and intel.get("epss_error"):
                st.warning(f"EPSS unavailable: {intel['epss_error']}")
            else:
                st.info("EPSS result not available for this CVE.")
            if kev and not (intel or {}).get("kev_error"):
                if kev.get("listed"):
                    st.error("CISA KEV: this CVE is listed")
                    st.caption(f"Added {kev.get('date_added') or 'date not supplied'} · {kev.get('vendor_project') or ''} {kev.get('product') or ''}")
                else:
                    st.success("CISA KEV: not found in retrieved catalogue")
                    st.caption(f"Catalogue date: {kev.get('catalog_date_released') or 'not supplied'}")
            elif intel and intel.get("kev_error"):
                st.warning(f"CISA KEV unavailable: {intel['kev_error']}")
            st.caption("A missing or unavailable source is not represented as zero risk.")

        st.markdown("### Automated CISO action summary")
        with st.container(border=True):
            st.write(make_ciso_summary(result, intel))

        d1, d2 = st.columns(2)
        with d1:
            st.download_button(
                "Download scenario report (JSON)",
                data=json.dumps(result_to_payload(result, intel), indent=2, default=str),
                file_name=f"fairpulse_{result.scenario.cve_id.lower()}_report.json",
                mime="application/json",
                use_container_width=True,
            )
        with d2:
            st.download_button(
                "Download financial outputs (CSV)",
                data=result_to_csv(result),
                file_name=f"fairpulse_{result.scenario.cve_id.lower()}_outputs.csv",
                mime="text/csv",
                use_container_width=True,
            )
    else:
        st.markdown(
            '<div class="fp-panel"><div class="fp-panel-title">Ready for your first risk scenario</div>'
            '<p class="fp-muted">Enter a CVE, asset context, event-frequency assumptions and loss ranges in the left-hand panel. '
            'Then select <b>Run Monte Carlo Simulation</b>. The application will retrieve available threat intelligence and calculate the current and proposed loss distributions.</p>'
            '<div class="fp-callout">No KPI values are fabricated or displayed before a simulation completes.</div></div>',
            unsafe_allow_html=True,
        )
        st.markdown("### What the model will calculate")
        empty_cols = st.columns(3)
        empty_cols[0].markdown("**01 · Loss Event Frequency**\n\nAnnual threat-event frequency × vulnerability/susceptibility.")
        empty_cols[1].markdown("**02 · Loss Magnitude**\n\nPrimary and secondary loss distributions per successful event.")
        empty_cols[2].markdown("**03 · Financial decision**\n\nCurrent ALE, target ALE, risk reduction and net ROSI.")

with lec_tab:
    st.markdown("## Loss distribution")
    st.markdown("Inspect the distribution and the probability of exceeding different annual loss amounts.")
    if result:
        st.plotly_chart(loss_exceedance_figure(result), use_container_width=True, key="distribution_loss_exceedance", config={"displaylogo": False, "responsive": True})
        st.plotly_chart(loss_distribution_figure(result), use_container_width=True, key="distribution_loss_histogram", config={"displaylogo": False, "responsive": True})
        st.plotly_chart(percentile_comparison_figure(result), use_container_width=True, key="distribution_percentile_comparison", config={"displaylogo": False, "responsive": True})
        st.markdown("### Loss percentile comparison")
        rows = []
        for key, label in [("p50", "50th percentile"), ("p75", "75th percentile"), ("p90", "90th percentile"), ("p95", "95th percentile"), ("p99", "99th percentile")]:
            rows.append({"Percentile": label, "Current state": money(result.current_percentiles[key], result.scenario.currency), "Proposed state": money(result.target_percentiles[key], result.scenario.currency)})
        st.dataframe(rows, use_container_width=True, hide_index=True)
        st.caption(f"Probability of no loss event in a simulated year: current {percent(result.current_zero_loss_probability)} · proposed {percent(result.target_zero_loss_probability)}.")
        with st.expander("How to read this chart"):
            st.write("The Loss Exceedance Curve (LEC) plots annual aggregate loss on the horizontal axis and the empirical probability of meeting or exceeding that loss on the vertical axis. It is based on the simulated annual losses, not a guaranteed forecast. The percentile chart reports quantiles of the same simulated distribution.")
    else:
        st.info("Run a simulation from the scenario panel to populate the loss distribution charts.")

with roi_tab:
    st.markdown("## Mitigation return on security investment")
    st.markdown("Compare the current control assumptions with the proposed state and the annualised cost of the mitigation.")
    if result:
        c = result.scenario.currency
        a, b, d = st.columns(3)
        a.metric("Annual risk reduction", money(result.risk_reduction, c))
        b.metric("Annualised mitigation cost", money(result.annualised_mitigation_cost, c))
        d.metric("Net annual benefit", money(result.net_annual_benefit, c), delta="Positive" if result.net_annual_benefit > 0 else "Non-positive", delta_color="normal")
        maturity_current_effectiveness = result.current_control_effectiveness
        maturity_target_effectiveness = result.target_control_effectiveness
        roi_matrix = [
            {"Metric": "Control maturity", "Current state": f"{result.scenario.current_control_maturity:.0f}%", "Proposed state / result": f"{result.scenario.target_control_maturity:.0f}%"},
            {"Metric": "Derived control-effectiveness assumption", "Current state": f"{maturity_current_effectiveness:.1%}", "Proposed state / result": f"{maturity_target_effectiveness:.1%}"},
            {"Metric": "Annualized Loss Expectancy", "Current state": money(result.current_ale, c), "Proposed state / result": money(result.target_ale, c)},
            {"Metric": "P95 annual loss", "Current state": money(result.current_percentiles["p95"], c), "Proposed state / result": money(result.target_percentiles["p95"], c)},
            {"Metric": "Risk reduction", "Current state": "—", "Proposed state / result": money(result.risk_reduction, c)},
            {"Metric": "Annualised mitigation cost", "Current state": "—", "Proposed state / result": money(result.annualised_mitigation_cost, c)},
            {"Metric": "Net annual benefit", "Current state": "—", "Proposed state / result": money(result.net_annual_benefit, c)},
            {"Metric": "Net ROSI", "Current state": "—", "Proposed state / result": f"{result.rosi_percent:,.1f}%" if result.rosi_percent is not None else "N/A"},
        ]
        st.markdown("### Mitigation comparison matrix")
        st.dataframe(roi_matrix, use_container_width=True, hide_index=True)
        st.caption("Derived effectiveness is the analyst-selected maturity calibration, not an observed control test result.")
        st.plotly_chart(roi_bridge_figure(result), use_container_width=True, key="roi_financial_bridge", config={"displaylogo": False, "responsive": True})
        if result.rosi_percent is not None:
            if result.rosi_percent > 0:
                st.success(f"Under the entered assumptions, modelled net ROSI is {result.rosi_percent:,.1f}%.")
            elif result.rosi_percent < 0:
                st.warning(f"Under the entered assumptions, modelled net ROSI is {result.rosi_percent:,.1f}%. Annualised cost exceeds modelled risk reduction.")
            else:
                st.info("Under the entered assumptions, modelled net ROSI is 0%.")
        else:
            st.info("ROSI is undefined because annualised mitigation cost is zero.")
        if result.payback_years is not None:
            st.metric("Simple upfront-cost payback", f"{result.payback_years:,.2f} years")
        else:
            st.caption("No simple payback period is demonstrated after recurring mitigation cost under the entered assumptions.")
        with st.expander("ROSI calculation and cost basis"):
            st.latex(r"\text{Annualised cost} = \frac{\text{One-off cost}}{\text{Useful life}} + \text{Annual operating cost}")
            st.latex(r"\text{Net ROSI} = \frac{\text{Current ALE} - \text{Target ALE} - \text{Annualised cost}}{\text{Annualised cost}} \times 100")
            st.write("The application uses straight-line annualisation of the one-off mitigation cost. It does not discount future cash flows, model tax effects, or monetise non-financial benefits. Ensure the useful-life and operating-cost assumptions match the investment decision horizon.")
    else:
        st.info("Run a simulation to calculate the proposed-state ALE and mitigation ROI.")

with governance_tab:
    st.markdown("## Regulatory crosswalk")
    st.markdown("Indicative relationships between this vulnerability-risk workflow and selected governance requirements or controls.")
    mappings = all_mappings()
    framework_filter = st.multiselect(
        "Frameworks",
        ["EU DORA", "NIS2", "ISO/IEC 27001:2022"],
        default=["EU DORA", "NIS2", "ISO/IEC 27001:2022"],
    )
    filtered = [m for m in mappings if m["framework"] in framework_filter]
    for mapping in filtered:
        with st.expander(f"{mapping['framework']} · {mapping['reference']} — {mapping['title']}"):
            st.write(mapping["relevance"])
            st.markdown(f"**Evidence to retain:** {mapping['evidence_to_retain']}")
            st.markdown("**Related topics:** " + " · ".join(mapping["topics"]))
            st.markdown(f"[Open source framework text]({mapping['url']})")
    st.warning("A crosswalk is not a legal opinion, a complete control assessment or evidence of compliance. Applicability depends on entity scope, national implementation, regulatory guidance and the organisation's circumstances.")

    st.markdown("---")
    st.markdown("## Methodology and model boundaries")
    st.markdown("### Model structure")
    st.latex(r"\text{Loss Event Frequency} = \text{Threat Event Frequency} \times \text{Vulnerability}")
    st.latex(r"\text{Vulnerability proxy} = \text{Base susceptibility} \times (1 - \text{Control effectiveness})")
    st.latex(r"\text{Annual loss} = \sum_{j=1}^{N} (\text{Primary loss}_j + \text{Secondary loss}_j)")
    st.markdown("### Assumptions you must be able to defend")
    st.markdown(
        "- **Threat Event Frequency (TEF):** triangular distribution in events per year, entered by the analyst.\n"
        "- **Base susceptibility:** triangular probability of a loss event per threat event before the modelled control effect.\n"
        "- **Control maturity calibration:** maturity is mapped linearly to an assumed maximum effectiveness at 100% maturity. This is an explicit portfolio-model assumption, not a FAIR-prescribed conversion.\n"
        "- **Loss magnitude:** primary and secondary per-event losses are independently sampled from triangular distributions.\n"
        "- **Annual aggregation:** loss-event frequency is represented as a Poisson process; annual loss is the sum of simulated event severities.\n"
        "- **Asset value:** contextual exposure reference only. It is not used as a hard cap or automatically treated as the expected loss."
    )
    st.markdown("### Threat-intelligence interpretation")
    st.markdown(
        "FIRST EPSS estimates the probability that a vulnerability will be exploited in the wild over the next 30 days. CISA KEV records vulnerabilities known to have been exploited in the wild. Neither source, on its own, tells FairPulse the annual number of attack attempts against a particular organisation or the probability that its specific asset will be compromised. FairPulse surfaces these sources as evidence for analyst judgement rather than inserting them into the model as unsupported multipliers."
    )
    st.markdown("### Limitations")
    st.markdown(
        "- Results are conditional on user-entered ranges and assumptions; they are not guaranteed forecasts.\n"
        "- Triangular distributions are convenient elicitation tools, not empirically validated distributions for every organisation.\n"
        "- The current implementation does not model dependencies between events, threat actors, vulnerabilities, correlated business losses, insurance recoveries, discount rates or changing threat conditions over time.\n"
        "- The control-maturity mapping needs organisation-specific calibration before operational use.\n"
        "- This portfolio application is not a certified FAIR Tool, audit opinion, legal opinion or compliance determination."
    )
    st.markdown("### Source references")
    st.markdown(
        "- [FIRST EPSS API](https://api.first.org/epss/)\n"
        "- [CISA Known Exploited Vulnerabilities catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)\n"
        "- [FAIR Institute](https://www.fairinstitute.org/)\n"
        "- [DORA — Regulation (EU) 2022/2554](https://eur-lex.europa.eu/eli/reg/2022/2554/oj)\n"
        "- [NIS2 — Directive (EU) 2022/2555](https://eur-lex.europa.eu/eli/dir/2022/2555/oj)\n"
        "- [ISO/IEC 27001](https://www.iso.org/standard/27001)"
    )

# ---------------------------------------------------------------------------
# Footer
# ---------------------------------------------------------------------------
st.markdown('<div class="fp-divider"></div>', unsafe_allow_html=True)
footer_left, footer_right = st.columns([3, 2])
with footer_left:
    st.markdown("**FAIRPULSE** · Cyber Risk Quantification")
    st.caption("Open-source portfolio project · Built with Python, Streamlit, NumPy and Plotly")
with footer_right:
    st.markdown(
        '[GitHub](https://github.com/craig2904/fairpulse)  ·  '
        '[LinkedIn](https://www.linkedin.com/in/craig-c-manohar-863b252b5/)',
        unsafe_allow_html=False,
    )
    st.caption("Global / remote · Live application availability depends on the Streamlit Community Cloud deployment and its upstream data sources.")
st.caption("FairPulse provides illustrative decision support. Validate asset exposure, threat assumptions, control effectiveness, loss estimates and legal applicability with qualified stakeholders before relying on results.")
st.markdown(
    "<div style='text-align:center; color:#7B8494; font-size:12px; "
    "padding:18px 0 8px 0;'>"
    "© 2026 Craig C. Manohar. All rights reserved. "
    "Built with purpose."
    "</div>",
    unsafe_allow_html=True
)
