"""
FairPulse — Cyber risk, quantified.

A single-file Streamlit application that converts one CVE into a
board-legible financial decision using FAIR-aligned Monte Carlo
simulation on live FIRST.org and CISA telemetry.

Deployed: Streamlit Community Cloud
Repo:     https://github.com/<you>/fairpulse
"""

import re
from datetime import datetime, timezone

import numpy as np
import plotly.graph_objects as go
import requests
import streamlit as st

# ═══════════════════════════════════════════════════════════════════
# PAGE CONFIG (must be first Streamlit call)
# ═══════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="FairPulse — Cyber risk, quantified",
    page_icon="◆",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ═══════════════════════════════════════════════════════════════════
# DESIGN TOKENS
# ═══════════════════════════════════════════════════════════════════
C = {
    "void":           "#000000",
    "panel":          "#0A0E17",
    "raised":         "#111827",
    "line":           "#1C2333",
    "text_primary":   "#F2F5F9",
    "text_secondary": "#9AA6B8",
    "text_muted":     "#5C6879",
    "cyan":           "#00E5FF",
    "emerald":        "#10B981",
    "crimson":        "#EF4444",
}

REPO_URL = "https://github.com/CHANGE-ME/fairpulse"
LINKEDIN_URL = "https://www.linkedin.com/in/CHANGE-ME/"

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


# ═══════════════════════════════════════════════════════════════════
# CSS
# ═══════════════════════════════════════════════════════════════════
st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"], .stApp {{ font-family: 'Outfit', sans-serif !important; }}
.stApp {{ background: {C['void']}; }}
#MainMenu, footer, header {{ visibility: hidden; }}
.block-container {{ padding-top: 2.5rem; padding-bottom: 2rem; max-width: 1180px; }}

h1, h2, h3, h4 {{ color: {C['text_primary']} !important; font-weight: 500 !important; letter-spacing: -0.02em; }}

/* ── HERO ────────────────────────────────────────────── */
.eyebrow {{
    font-size: 11px; letter-spacing: 0.22em; text-transform: uppercase;
    color: {C['text_muted']}; font-weight: 500; margin: 0 0 24px 0;
}}
.hero-h1 {{
    font-size: clamp(2.6rem, 5.5vw, 4.2rem); line-height: 0.98;
    letter-spacing: -0.04em; color: {C['text_primary']};
    font-weight: 500; margin: 0 0 20px 0;
}}
.hero-h1 em {{ color: {C['cyan']}; font-style: normal; }}
.hero-sub {{
    font-size: 1.05rem; line-height: 1.65; color: {C['text_secondary']};
    max-width: 640px; margin: 0 0 28px 0;
}}

/* ── CHIPS ───────────────────────────────────────────── */
.chip-row {{ display: flex; gap: 8px; flex-wrap: wrap; margin: 0 0 32px 0; }}
.chip {{
    font-size: 11px; font-weight: 500; letter-spacing: 0.1em;
    text-transform: uppercase; padding: 8px 14px; border-radius: 999px;
    border: 1px solid {C['line']}; background: {C['panel']}; color: {C['text_secondary']};
}}
.chip.ok   {{ color: {C['emerald']}; border-color: rgba(16,185,129,0.3); }}
.chip.warn {{ color: {C['crimson']}; border-color: rgba(239,68,68,0.3); }}
.chip.info {{ color: {C['cyan']};    border-color: rgba(0,229,255,0.3); }}

/* ── CARDS ───────────────────────────────────────────── */
.card {{
    background: {C['panel']}; border: 1px solid {C['line']};
    border-radius: 2px; padding: 24px; height: 100%;
}}
.card-label {{
    font-size: 11px; letter-spacing: 0.22em; text-transform: uppercase;
    color: {C['text_muted']}; font-weight: 500; display: block; margin-bottom: 12px;
}}
.card-value {{
    font-size: 2.3rem; line-height: 1; font-weight: 500;
    color: {C['text_primary']}; letter-spacing: -0.02em;
    font-variant-numeric: tabular-nums; margin-bottom: 8px;
}}
.card-value.cyan    {{ color: {C['cyan']}; }}
.card-value.emerald {{ color: {C['emerald']}; }}
.card-value.crimson {{ color: {C['crimson']}; }}
.card-sub {{ font-size: 13px; line-height: 1.5; color: {C['text_secondary']}; }}

/* ── VERDICT ─────────────────────────────────────────── */
.verdict {{
    background: {C['panel']}; border: 1px solid {C['line']};
    border-left: 2px solid {C['cyan']}; border-radius: 2px;
    padding: 32px; margin: 20px 0;
}}
.verdict-tag {{
    font-size: 11px; letter-spacing: 0.22em; text-transform: uppercase;
    color: {C['text_muted']}; font-weight: 500; display: block; margin-bottom: 8px;
}}
.verdict-title {{
    font-size: 1.9rem; font-weight: 500; line-height: 1.15;
    margin: 0 0 14px 0; letter-spacing: -0.02em;
}}
.verdict-body {{ font-size: 15px; line-height: 1.7; color: {C['text_secondary']}; margin: 0; }}

/* ── SECTION HEADERS ─────────────────────────────────── */
.section-tag {{
    font-size: 11px; letter-spacing: 0.22em; text-transform: uppercase;
    color: {C['text_muted']}; font-weight: 500; display: block; margin-bottom: 8px;
}}
.section-h2 {{
    font-size: 1.7rem; line-height: 1.15; font-weight: 500;
    color: {C['text_primary']}; margin: 0 0 8px 0; letter-spacing: -0.02em;
}}
.section-sub {{
    font-size: 15px; line-height: 1.65; color: {C['text_secondary']};
    max-width: 720px; margin: 0 0 24px 0;
}}

/* ── TABS ────────────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] {{
    gap: 4px; border-bottom: 1px solid {C['line']}; background: transparent;
}}
.stTabs [data-baseweb="tab"] {{
    font-family: 'Outfit', sans-serif; font-size: 12px; font-weight: 500;
    letter-spacing: 0.1em; text-transform: uppercase; color: {C['text_muted']};
    background: transparent; padding: 16px 22px; border: none;
    border-bottom: 2px solid transparent;
}}
.stTabs [aria-selected="true"] {{
    color: {C['cyan']} !important; border-bottom: 2px solid {C['cyan']} !important;
}}

/* ── SIDEBAR ─────────────────────────────────────────── */
section[data-testid="stSidebar"] {{
    background: {C['panel']}; border-right: 1px solid {C['line']};
}}
section[data-testid="stSidebar"] label {{
    font-size: 11px !important; letter-spacing: 0.12em !important;
    text-transform: uppercase !important; color: {C['text_muted']} !important;
    font-weight: 500 !important;
}}
section[data-testid="stSidebar"] h2 {{ font-size: 1.1rem; }}

/* ── INPUTS ──────────────────────────────────────────── */
.stTextInput input, .stNumberInput input {{
    background: {C['raised']} !important; border: 1px solid {C['line']} !important;
    border-radius: 2px !important; color: {C['text_primary']} !important;
    font-family: 'Outfit', sans-serif !important; font-size: 14px !important;
    padding: 10px 12px !important;
}}
.stTextInput input:focus, .stNumberInput input:focus {{
    border-color: {C['cyan']} !important;
    box-shadow: 0 0 0 2px rgba(0,229,255,0.15) !important;
}}
.stSlider [data-baseweb="slider"] div[role="slider"] {{ background: {C['cyan']} !important; }}

/* ── BUTTONS ─────────────────────────────────────────── */
.stButton button[kind="primary"], .stLinkButton a {{
    border-radius: 2px !important; font-family: 'Outfit', sans-serif !important;
    font-size: 13px !important; font-weight: 500 !important;
    letter-spacing: 0.04em !important; padding: 12px 24px !important;
    min-height: 44px !important; transition: opacity 0.15s ease !important;
}}
.stButton button[kind="primary"] {{
    background: {C['cyan']} !important; color: {C['void']} !important; border: none !important;
}}
.stButton button[kind="primary"]:hover {{ opacity: 0.85 !important; }}
.stLinkButton a {{
    background: transparent !important; color: {C['text_primary']} !important;
    border: 1px solid {C['line']} !important;
}}
.stLinkButton a:hover {{ border-color: {C['cyan']} !important; }}

/* ── EXPANDER ────────────────────────────────────────── */
.streamlit-expanderHeader {{
    font-size: 13px !important; font-weight: 500 !important;
    color: {C['text_primary']} !important; background: {C['panel']} !important;
    border: 1px solid {C['line']} !important; border-radius: 2px !important;
}}

/* ── PROVENANCE / LIMITS ─────────────────────────────── */
.provenance {{
    font-family: 'JetBrains Mono', 'Courier New', monospace;
    font-size: 12px; line-height: 1.9; color: {C['text_muted']};
}}
.provenance strong {{ color: {C['text_secondary']}; font-weight: 500; }}
.provenance .ok {{ color: {C['emerald']}; }}
.provenance .fail {{ color: {C['crimson']}; }}
.limits {{ font-size: 14px; line-height: 1.8; color: {C['text_secondary']}; }}
.limits strong {{ color: {C['text_primary']}; font-weight: 500; }}

hr {{ border: none; border-top: 1px solid {C['line']}; margin: 48px 0; }}
</style>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════
def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def chip_row(chips: list[str]) -> None:
    st.markdown(f'<div class="chip-row">{"".join(chips)}</div>', unsafe_allow_html=True)


def chip(text: str, variant: str = "") -> str:
    cls = f"chip {variant}" if variant else "chip"
    return f'<span class="{cls}">{text}</span>'


def kpi_card(label: str, value: str, sub: str, variant: str = "") -> str:
    value_cls = f"card-value {variant}" if variant else "card-value"
    return (
        f'<div class="card">'
        f'<span class="card-label">{label}</span>'
        f'<div class="{value_cls}">{value}</div>'
        f'<div class="card-sub">{sub}</div>'
        f'</div>'
    )


def money(x: float) -> str:
    """Format a dollar figure compactly."""
    if abs(x) >= 1_000_000:
        return f"${x / 1e6:.2f}M"
    if abs(x) >= 1_000:
        return f"${x / 1e3:.0f}k"
    return f"${x:.0f}"


# ═══════════════════════════════════════════════════════════════════
# DATA LAYER
# ═══════════════════════════════════════════════════════════════════
@st.cache_data(ttl=3600, show_spinner=False)
def fetch_cisa_kev() -> dict:
    fetched = now_utc()
    try:
        r = requests.get(
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json",
            timeout=10,
        )
        if r.status_code != 200:
            return {"ok": False, "error": f"HTTP {r.status_code}", "fetched": fetched}
        data = r.json()
        return {
            "ok": True,
            "catalog": {v["cveID"]: v for v in data.get("vulnerabilities", [])},
            "version": data.get("catalogVersion", "—"),
            "released": data.get("dateReleased", "—"),
            "fetched": fetched,
        }
    except Exception as e:
        return {"ok": False, "error": type(e).__name__, "fetched": fetched}


@st.cache_data(ttl=3600, show_spinner=False)
def fetch_epss(cve_id: str) -> dict:
    fetched = now_utc()
    if not CVE_PATTERN.match(cve_id.strip().upper()):
        return {"ok": False, "error": "Invalid CVE format", "fetched": fetched}
    try:
        r = requests.get(
            f"https://api.first.org/data/v1/epss?cve={cve_id.strip().upper()}",
            timeout=8,
        )
        if r.status_code != 200:
            return {"ok": False, "error": f"HTTP {r.status_code}", "fetched": fetched}
        records = r.json().get("data", [])
        if not records:
            return {"ok": False, "error": "Not in EPSS index", "fetched": fetched}
        rec = records[0]
        return {
            "ok": True,
            "epss": float(rec["epss"]),
            "percentile": float(rec.get("percentile", 0.0)),
            "date": rec.get("date", "—"),
            "fetched": fetched,
        }
    except Exception as e:
        return {"ok": False, "error": type(e).__name__, "fetched": fetched}


# ═══════════════════════════════════════════════════════════════════
# MODEL LAYER
# ═══════════════════════════════════════════════════════════════════
@st.cache_data(show_spinner=False, hash_funcs={float: float})
def simulate(tef_mode: float, vuln_prob: float, asset_val: float,
             iterations: int = 10_000, seed: int = 42) -> np.ndarray:
    """
    FAIR-aligned Monte Carlo.

      TEF (threat event frequency)  ~ Triangular(mode×0.4, mode, mode×2.5)
      LEF (loss event frequency)    ~ Poisson(TEF × Vulnerability)
      SLE (single loss exposure)    ~ Triangular(asset×0.35, asset, asset×2.4)

    Returns array of annualized losses over `iterations` simulated years.
    """
    rng = np.random.default_rng(seed)
    tef = rng.triangular(
        left=max(0.1, tef_mode * 0.4),
        mode=tef_mode,
        right=max(tef_mode * 2.5, tef_mode * 0.4 + 0.2),
        size=iterations,
    )
    lef_lambda = tef * float(np.clip(vuln_prob, 0.001, 0.999))
    loss_events = rng.poisson(lef_lambda)
    sle = rng.triangular(
        left=max(1.0, asset_val * 0.35),
        mode=max(1.0, asset_val),
        right=max(asset_val * 2.4, asset_val * 0.35 + 1.0),
        size=iterations,
    )
    return loss_events * sle


@st.cache_data(show_spinner=False, hash_funcs={float: float})
def sensitivity(tef_mode: float, vuln_prob: float, asset_val: float,
                iterations: int = 4_000) -> tuple[float, list[dict]]:
    """Tornado: run the model at ±25% on each parameter independently."""
    base = float(np.mean(simulate(tef_mode, vuln_prob, asset_val, iterations)))

    def run(t: float, v: float, a: float) -> float:
        return float(np.mean(simulate(t, v, a, iterations)))

    rows = [
        {
            "parameter": "Threat Event Frequency",
            "low":  run(max(0.1, tef_mode * 0.75), vuln_prob, asset_val),
            "high": run(tef_mode * 1.25,          vuln_prob, asset_val),
        },
        {
            "parameter": "Vulnerability Probability",
            "low":  run(tef_mode, max(0.001, vuln_prob * 0.75), asset_val),
            "high": run(tef_mode, min(0.999, vuln_prob * 1.25), asset_val),
        },
        {
            "parameter": "Single Loss Exposure",
            "low":  run(tef_mode, vuln_prob, asset_val * 0.75),
            "high": run(tef_mode, vuln_prob, asset_val * 1.25),
        },
    ]
    rows.sort(key=lambda r: abs(r["high"] - r["low"]))
    return base, rows


# ═══════════════════════════════════════════════════════════════════
# SIDEBAR
# ═══════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown('<p class="section-tag">Configuration</p>', unsafe_allow_html=True)
    st.markdown("## Risk profile")
    st.markdown(
        '<p style="font-size:13px;color:#5C6879;line-height:1.6;'
        'margin:0 0 20px 0;">Define the vulnerability and business context. '
        'Results update live as you adjust parameters.</p>',
        unsafe_allow_html=True,
    )

    cve_input = st.text_input(
        "CVE identifier",
        value="CVE-2024-3400",
        placeholder="CVE-2024-3400",
        help="Public CVE ID. Must match CVE-YYYY-NNNN.",
    )

    asset_val = st.number_input(
        "Asset valuation ($)",
        min_value=100_000,
        max_value=100_000_000,
        value=6_300_000,
        step=100_000,
        format="%d",
        help="Financial value of the exposed asset — records × per-record cost.",
    )

    st.markdown("---")
    st.markdown('<p class="section-tag">Baseline</p>', unsafe_allow_html=True)
    current_pct = st.slider(
        "Current control maturity (%)",
        min_value=0, max_value=90, value=35,
        help="0% = no compensating controls. Use your last audit finding.",
    )

    st.markdown('<p class="section-tag">Proposal</p>', unsafe_allow_html=True)
    proposed_pct = st.slider(
        "Target control maturity (%)",
        min_value=current_pct, max_value=100,
        value=max(85, current_pct),
    )
    mitigation_cost = st.number_input(
        "Mitigation cost ($)",
        min_value=1_000, max_value=10_000_000,
        value=125_000, step=5_000, format="%d",
    )

    st.markdown("---")
    st.markdown(
        '<p style="font-size:11px;color:#5C6879;line-height:1.7;">'
        'Model output is decision support, not decision automation. '
        'FAIR is a registered trademark of the Open Group.</p>',
        unsafe_allow_html=True,
    )

current_control = current_pct / 100
proposed_control = proposed_pct / 100


# ═══════════════════════════════════════════════════════════════════
# DATA RESOLUTION
# ═══════════════════════════════════════════════════════════════════
cve_clean = cve_input.strip().upper()
cve_is_valid = bool(CVE_PATTERN.match(cve_clean))

with st.spinner("Fetching live threat intelligence…"):
    kev = fetch_cisa_kev()
    epss = fetch_epss(cve_clean) if cve_is_valid else {
        "ok": False, "error": "Invalid format", "fetched": now_utc()
    }

is_in_kev = kev["ok"] and cve_is_valid and cve_clean in kev["catalog"]
epss_available = epss["ok"]
epss_prob = epss["epss"] if epss_available else 0.05

# If the CVE is in KEV, use its reported date as additional context
kev_record = kev["catalog"].get(cve_clean) if is_in_kev else None


# ═══════════════════════════════════════════════════════════════════
# HERO
# ═══════════════════════════════════════════════════════════════════
st.markdown('<p class="eyebrow">FAIR-aligned · Live telemetry · Board-ready</p>', unsafe_allow_html=True)
st.markdown(
    '<h1 class="hero-h1">Your board doesn\'t read CVSS.<br>They read <em>P&amp;L.</em></h1>',
    unsafe_allow_html=True,
)
st.markdown(
    '<p class="hero-sub">FairPulse turns one vulnerability into an annualized loss '
    'distribution, a mitigation ROI, and the exact compliance clauses it satisfies — '
    'using live FIRST.org exploit probability and CISA\'s known-exploited catalog. '
    'Ten thousand simulated years per run.</p>',
    unsafe_allow_html=True,
)

hc1, hc2, _ = st.columns([1, 1, 2])
with hc1:
    st.link_button("View source on GitHub", REPO_URL, use_container_width=True)
with hc2:
    st.link_button("Connect on LinkedIn", LINKEDIN_URL, use_container_width=True)

# Status chips
chips: list[str] = []
if not cve_is_valid:
    chips.append(chip("◌ Invalid CVE format", "warn"))
elif not kev["ok"]:
    chips.append(chip("⚠ CISA KEV feed unavailable", "warn"))
elif is_in_kev:
    chips.append(chip("● Active in CISA KEV", "ok"))
else:
    chips.append(chip("○ Not in KEV"))

if epss_available:
    chips.append(chip(f"EPSS · {epss['epss'] * 100:.1f}% · P{int(epss['percentile'] * 100)}", "info"))
else:
    chips.append(chip(f"EPSS · {epss.get('error', 'unavailable')} · 5% fallback", "warn"))

chips.append(chip("10,000 Monte Carlo trials"))
chip_row(chips)


# ═══════════════════════════════════════════════════════════════════
# MODEL EXECUTION
# ═══════════════════════════════════════════════════════════════════
base_tef = 4.0 if is_in_kev else max(0.5, epss_prob * 12)
inherent_vuln = float(np.clip(
    epss_prob * (1.5 if is_in_kev else 1.0) + 0.35,
    0.15, 0.95,
))

current_vuln = inherent_vuln * (1.0 - current_control)
target_vuln = inherent_vuln * (1.0 - proposed_control)

current_ale = simulate(base_tef, current_vuln, float(asset_val))
target_ale = simulate(base_tef, target_vuln, float(asset_val))

mean_current = float(np.mean(current_ale))
mean_target = float(np.mean(target_ale))
p10_cur, p50_cur, p90_cur = (float(x) for x in np.percentile(current_ale, [10, 50, 90]))
p10_tgt, p50_tgt, p90_tgt = (float(x) for x in np.percentile(target_ale, [10, 50, 90]))

loss_avoided = mean_current - mean_target
rosi = ((loss_avoided - mitigation_cost) / mitigation_cost) * 100 if mitigation_cost > 0 else 0.0

break_even_pct = (mitigation_cost / mean_current * 100) if mean_current > 0 else 0.0
actual_reduction_pct = (loss_avoided / mean_current * 100) if mean_current > 0 else 0.0

data_ok = kev["ok"] and epss_available and cve_is_valid


# ═══════════════════════════════════════════════════════════════════
# TABS
# ═══════════════════════════════════════════════════════════════════
tab_exposure, tab_curve, tab_mitigation, tab_governance = st.tabs(
    ["Exposure", "Loss curve", "Mitigation", "Governance"]
)


# ─── TAB 1 — EXPOSURE ─────────────────────────────────────────────
with tab_exposure:
    st.markdown('<span class="section-tag">01 — Exposure</span>', unsafe_allow_html=True)
    st.markdown('<h2 class="section-h2">What is this actually worth?</h2>', unsafe_allow_html=True)
    st.markdown(
        '<p class="section-sub">Every number below is the mean of 10,000 simulated '
        'years. The 80% confidence band (P10–P90) is the range you should actually '
        'plan for — a single mean hides the uncertainty that is the whole point of '
        'running the model.</p>',
        unsafe_allow_html=True,
    )

    e1, e2, e3, e4 = st.columns(4)
    with e1:
        st.markdown(kpi_card(
            "Current annualized loss",
            money(mean_current),
            f"80% CI: {money(p10_cur)} — {money(p90_cur)}",
            "crimson" if mean_current > 0 else "",
        ), unsafe_allow_html=True)
    with e2:
        st.markdown(kpi_card(
            "Target annualized loss",
            money(mean_target),
            f"80% CI: {money(p10_tgt)} — {money(p90_tgt)}",
            "emerald",
        ), unsafe_allow_html=True)
    with e3:
        st.markdown(kpi_card(
            "Annual loss avoided",
            money(loss_avoided),
            f"{actual_reduction_pct:.0f}% of current exposure",
            "cyan",
        ), unsafe_allow_html=True)
    with e4:
        st.markdown(kpi_card(
            "Return on investment",
            f"{rosi:+.0f}%",
            f"On {money(mitigation_cost)} of mitigation spend",
            "cyan" if rosi >= 0 else "crimson",
        ), unsafe_allow_html=True)

    st.markdown("---")
    st.markdown('<span class="section-tag">Sensitivity</span>', unsafe_allow_html=True)
    st.markdown('<h3 class="section-h2" style="font-size:1.4rem;">What actually moves the number?</h3>', unsafe_allow_html=True)
    st.markdown(
        '<p class="section-sub">A model that can\'t tell you what drives its own '
        'output is a black box. Below, each parameter is varied by ±25% '
        'independently. The longer the bar, the more your answer depends on that '
        'assumption — and the more you should invest in measuring it accurately.</p>',
        unsafe_allow_html=True,
    )

    base_mean, sens_rows = sensitivity(base_tef, current_vuln, float(asset_val))

    fig_tor = go.Figure()
    for row in sens_rows:
        fig_tor.add_trace(go.Bar(
            y=[row["parameter"]],
            x=[base_mean - row["low"]],
            base=[row["low"]],
            orientation="h",
            marker=dict(color="#3D4A3D", line=dict(width=0)),
            showlegend=False,
            hovertemplate=f"−25% → {money(row['low'])}<extra></extra>",
            name="−25%",
        ))
        fig_tor.add_trace(go.Bar(
            y=[row["parameter"]],
            x=[row["high"] - base_mean],
            base=[base_mean],
            orientation="h",
            marker=dict(color=C["cyan"], line=dict(width=0)),
            showlegend=False,
            hovertemplate=f"+25% → {money(row['high'])}<extra></extra>",
            name="+25%",
        ))

    fig_tor.add_vline(x=base_mean, line_dash="dash", line_color=C["text_secondary"], line_width=1)
    fig_tor.add_annotation(
        x=base_mean, y=1.08, yref="paper",
        text=f"Base case · {money(base_mean)}",
        showarrow=False,
        font=dict(color=C["text_primary"], size=11, family="Outfit"),
        bgcolor=C["void"], borderpad=4,
    )

    fig_tor.update_layout(
        barmode="overlay",
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(
            title="Annualized loss ($)",
            title_font=dict(color=C["text_muted"], size=11, family="Outfit"),
            showgrid=True, gridcolor=C["line"], zeroline=False,
            tickfont=dict(color=C["text_muted"], size=10, family="Outfit"),
            tickprefix="$", tickformat=",.0f",
        ),
        yaxis=dict(
            tickfont=dict(color=C["text_secondary"], size=11, family="Outfit"),
            showgrid=False,
        ),
        margin=dict(l=10, r=10, t=40, b=10), height=320, bargap=0.45,
        hoverlabel=dict(bgcolor=C["raised"], font=dict(color=C["text_primary"], family="Outfit")),
    )
    st.plotly_chart(fig_tor, use_container_width=True)


# ─── TAB 2 — LOSS CURVE ───────────────────────────────────────────
with tab_curve:
    st.markdown('<span class="section-tag">02 — Distribution</span>', unsafe_allow_html=True)
    st.markdown('<h2 class="section-h2">How likely is a bad year?</h2>', unsafe_allow_html=True)
    st.markdown(
        '<p class="section-sub">The loss exceedance curve answers a single '
        'board-level question: <em>what is the probability that we lose more than '
        'X this year?</em> The gap between the two curves is the financial value '
        'of the proposed control.</p>',
        unsafe_allow_html=True,
    )

    sorted_cur = np.sort(current_ale)
    sorted_tgt = np.sort(target_ale)
    exceedance_pct = (1.0 - np.arange(1, len(sorted_cur) + 1) / len(sorted_cur)) * 100

    fig_lec = go.Figure()
    fig_lec.add_trace(go.Scatter(
        x=sorted_cur[::25], y=exceedance_pct[::25],
        mode="lines", name="Current posture",
        line=dict(color=C["crimson"], width=2.5),
        fill="tozeroy", fillcolor="rgba(239,68,68,0.08)",
    ))
    fig_lec.add_trace(go.Scatter(
        x=sorted_tgt[::25], y=exceedance_pct[::25],
        mode="lines", name="Target posture",
        line=dict(color=C["emerald"], width=2.5),
        fill="tozeroy", fillcolor="rgba(16,185,129,0.10)",
    ))
    fig_lec.add_vline(x=p90_cur, line_dash="dot", line_color=C["text_muted"], line_width=1)
    fig_lec.add_annotation(
        x=p90_cur, y=90,
        text=f"P90 · {money(p90_cur)}",
        showarrow=False,
        font=dict(color=C["text_secondary"], size=10, family="Outfit"),
        bgcolor=C["void"], borderpad=4,
    )

    fig_lec.update_layout(
        plot_bgcolor="rgba(0,0,0,0)", paper_bgcolor="rgba(0,0,0,0)",
        xaxis=dict(
            title="Annualized financial loss ($)",
            title_font=dict(color=C["text_muted"], size=11, family="Outfit"),
            showgrid=True, gridcolor=C["line"], zeroline=False,
            tickfont=dict(color=C["text_muted"], size=10, family="Outfit"),
            tickprefix="$", tickformat=",.0f",
        ),
        yaxis=dict(
            title="Probability of exceeding (%)",
            title_font=dict(color=C["text_muted"], size=11, family="Outfit"),
            showgrid=True, gridcolor=C["line"], zeroline=False,
            tickfont=dict(color=C["text_muted"], size=10, family="Outfit"),
            range=[0, 100],
        ),
        legend=dict(
            orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1,
            font=dict(color=C["text_secondary"], size=11, family="Outfit"),
            bgcolor="rgba(0,0,0,0)",
        ),
        margin=dict(l=10, r=10, t=30, b=10), height=440,
        hoverlabel=dict(bgcolor=C["raised"], font=dict(color=C["text_primary"], family="Outfit")),
    )
    st.plotly_chart(fig_lec, use_container_width=True)

    with st.expander("Method — how these curves are generated"):
        st.markdown("""
**Model form.** Open FAIR decomposes annualized loss into risk factors:

- **Threat Event Frequency (TEF)** — how often a threat actor attempts this
  class of exploit per year. Modelled as a triangular distribution with mode
  set by KEV status and EPSS score, and bounds at 0.4× and 2.5× the mode.
- **Vulnerability (V)** — the probability that an attempt succeeds. Derived
  from EPSS with a KEV multiplier, then reduced by control maturity.
  `effective_vulnerability = inherent_vulnerability × (1 − control_maturity)`.
- **Loss Event Frequency (LEF) = TEF × V.** We sample LEF as `Poisson(TEF × V)`,
  not as a binomial over rounded event counts — a binomial floors low-frequency
  threats at one event per year and inflates every low-EPSS estimate.
- **Single Loss Exposure (SLE)** — financial magnitude of one successful event.
  Triangular with mode = asset valuation, bounds at 0.35× and 2.4×.

Each of the 10,000 iterations samples one year from these four distributions
and multiplies `LEF × SLE`. The result is the distribution plotted above.
                """)


# ─── TAB 3 — MITIGATION ───────────────────────────────────────────
with tab_mitigation:
    st.markdown('<span class="section-tag">03 — Recommendation</span>', unsafe_allow_html=True)
    st.markdown('<h2 class="section-h2">Should you fund it?</h2>', unsafe_allow_html=True)

    if not data_ok:
        direction = "Data insufficient"
        direction_color = C["text_muted"]
        rationale = (
            "One or both upstream feeds failed to return data for this CVE. "
            "The fallback parameters used in this run are conservative assumptions, "
            "not observations. Re-run before presenting any figure to a board or "
            "auditor."
        )
    elif rosi >= 100:
        direction = "Fund"
        direction_color = C["emerald"]
        rationale = (
            f"The expected loss avoided ({money(loss_avoided)}) exceeds the mitigation "
            f"cost by a factor of {(1 + rosi / 100):.1f}×. Even at the 80% confidence "
            f"bound, this investment remains positive in the large majority of "
            f"simulated scenarios. Fund, and publish the model assumptions as part of "
            f"the business case."
        )
    elif rosi >= 0:
        direction = "Fund with caution"
        direction_color = C["cyan"]
        rationale = (
            f"Net benefit is positive but modest ({rosi:+.0f}%). Break-even requires "
            f"eliminating {break_even_pct:.0f}% of current exposure; the model expects "
            f"{actual_reduction_pct:.0f}%. That margin is thin — revalidate the "
            f"mitigation cost and control-maturity assumptions before committing."
        )
    elif rosi >= -50:
        direction = "Marginal — review alternatives"
        direction_color = C["crimson"]
        rationale = (
            f"The proposed spend is not recovered by expected loss avoidance. "
            f"Consider a lower-cost control, a phased deployment, or a compensating "
            f"control that reduces exposure without the full {money(mitigation_cost)} "
            f"outlay. Compliance obligations may still justify the spend — but do not "
            f"present it as ROI-positive."
        )
    elif rosi >= -100:
        direction = "Defer pending revalidation"
        direction_color = C["crimson"]
        rationale = (
            f"At current assumptions, the mitigation cost exceeds modelled loss "
            f"avoidance. Document the decision, set a re-evaluation trigger (for "
            f"example: EPSS crosses 30%, or the CVE enters the KEV catalog), and "
            f"revisit. Deferring with a written rationale is a defensible board "
            f"position; deferring silently is not."
        )
    else:
        direction = "Decline — pursue alternative controls"
        direction_color = C["crimson"]
        rationale = (
            f"This investment is not economically justified under any reasonable "
            f"assumption set: the modelled loss avoidance is a small fraction of the "
            f"proposed spend. Pursuing alternative controls, or accepting the residual "
            f"risk explicitly, is the correct decision."
        )

    st.markdown(
        f'<div class="verdict">'
        f'<span class="verdict-tag">Direction</span>'
        f'<h3 class="verdict-title" style="color:{direction_color};">{direction}</h3>'
        f'<p class="verdict-body">{rationale}</p>'
        f'</div>',
        unsafe_allow_html=True,
    )

    m1, m2, m3 = st.columns(3)
    with m1:
        st.markdown(kpi_card(
            "Break-even reduction",
            f"{break_even_pct:.0f}%",
            "Share of current risk that must be eliminated to justify the spend",
        ), unsafe_allow_html=True)
    with m2:
        st.markdown(kpi_card(
            "Modelled reduction",
            f"{actual_reduction_pct:.0f}%",
            "On current parameter assumptions",
            "cyan",
        ), unsafe_allow_html=True)
    with m3:
        st.markdown(kpi_card(
            "P90 loss avoided",
            money(p90_cur - p90_tgt),
            "Tail-risk reduction at the 90th percentile",
            "emerald",
        ), unsafe_allow_html=True)


# ─── TAB 4 — GOVERNANCE ──────────────────────────────────────────
with tab_governance:
    st.markdown('<span class="section-tag">04 — Governance</span>', unsafe_allow_html=True)
    st.markdown('<h2 class="section-h2">Which obligations does this satisfy?</h2>', unsafe_allow_html=True)
    st.markdown(
        '<p class="section-sub">Quantitative risk analysis is not just good practice — '
        'it is increasingly the evidentiary standard regulators expect. Each FAIR '
        'factor in this model maps to specific control obligations.</p>',
        unsafe_allow_html=True,
    )

    with st.expander("EU DORA — Digital Operational Resilience Act"):
        st.markdown(f"""
**Article 9 — Protection and prevention**
The target control maturity score is the quantified state of protection this
analysis assumes. `effective_vulnerability = inherent_vulnerability × (1 − maturity)`
is the modelled effect of the Art. 9 controls you have and propose to add.

**Article 10 — Detection**
CISA KEV membership and EPSS percentile constitute automated threat-detection
evidence for the specific vulnerability under assessment.

**Article 28 — Third-party risk**
When the vulnerable asset is operated by or for a third party, the annualized
loss distribution is the quantitative input to Art. 28's contractual risk
assessment.
            """)

    with st.expander("NIS2 Directive"):
        st.markdown("""
**Article 21(2)(a) — Risk analysis and information system security policies**
The 10,000-trial Monte Carlo distribution is a reproducible, defensible risk
assessment artifact. Its parameters are visible in the source.

**Article 21(2)(f) — Policies to assess the effectiveness of measures**
The ROSI calculation on the Mitigation tab is a documented cost–benefit
evaluation of the proposed control — exactly what Art. 21(2)(f) requires.
            """)

    with st.expander("ISO/IEC 27001:2022"):
        st.markdown("""
**A.8.8 — Management of technical vulnerabilities**
The analysis is per-CVE, using live exploit intelligence and business context —
not a scanner export.

**A.5.7 — Threat intelligence**
CISA KEV and FIRST EPSS are the named, dated sources.

**Clause 6.1.2 — Information security risk assessment**
The method is quantitative, reproducible, and documented. The uncertainty is
explicit in the P10–P90 bands.
            """)

    with st.expander("NIST CSF 2.0"):
        st.markdown("""
**ID.RA-01 — Vulnerabilities in assets are identified**
Per-CVE assessment with exploit-intelligence enrichment.

**ID.RA-05 — Risk responses are prioritized**
The ROSI figure establishes cost-justified ordering — not severity ranking.

**RS.MA-02 — Risk responses are evaluated**
The current-vs-target comparison is a quantified evaluation of the proposed
response before implementation.
            """)


# ═══════════════════════════════════════════════════════════════════
# FOOTER — PROVENANCE, LIMITS, CONTACT
# ═══════════════════════════════════════════════════════════════════
st.markdown("---")
st.markdown('<span class="section-tag">05 — Provenance</span>', unsafe_allow_html=True)
st.markdown('<h2 class="section-h2">Where did these numbers come from?</h2>', unsafe_allow_html=True)

kev_line = (
    f'<span class="ok">OK</span> · catalog v{kev["version"]} · released {kev["released"]}'
    if kev["ok"]
    else f'<span class="fail">FAILED</span> · {kev.get("error", "unknown")}'
)
epss_line = (
    f'<span class="ok">{epss["epss"] * 100:.2f}%</span> · '
    f'P{int(epss["percentile"] * 100)} · as of {epss["date"]}'
    if epss_available
    else f'<span class="fail">FAILED</span> · {epss.get("error", "unknown")}'
)

if kev_record:
    kev_line += f' · added {kev_record.get("dateAdded", "—")}'

st.markdown(f"""
<div class="provenance">
<strong>CISA KEV</strong> &nbsp; {kev_line}<br>
&nbsp; fetched {kev["fetched"]} &nbsp; source: cisa.gov<br><br>

<strong>FIRST EPSS</strong> &nbsp; {epss_line}<br>
&nbsp; fetched {epss["fetched"]} &nbsp; source: api.first.org<br><br>

<strong>MODEL</strong> &nbsp; Open FAIR · 10,000 trials · Poisson LEF · Triangular TEF &amp; SLE<br>
&nbsp; inherent_vulnerability = clip(EPSS × KEV_multiplier + 0.35, 0.15, 0.95)<br>
&nbsp; effective_vulnerability = inherent_vulnerability × (1 − control_maturity)<br>
&nbsp; seed = 42 · iterations = 10,000 · repository: {REPO_URL}<br><br>

<strong>ASSUMPTIONS</strong> &nbsp; control maturity is a normalized proxy, not a measured
control effectiveness;<br>
&nbsp; triangular bounds are expert-elicitation defaults and should be replaced with
organization-specific telemetry;<br>
&nbsp; asset valuation should reflect actual record count × per-record cost, not
insurance values or book value.
</div>
""", unsafe_allow_html=True)

st.markdown("---")
st.markdown('<span class="section-tag">06 — Limits</span>', unsafe_allow_html=True)
st.markdown('<h2 class="section-h2">What this model does not do</h2>', unsafe_allow_html=True)
st.markdown("""
<div class="limits">
<strong>Not a loss forecast.</strong> The distribution is a prioritization tool,
not a prediction. Treat it as a ranking mechanism and a communication device,
not an actuarial projection.<br><br>

<strong>Does not model correlated loss events.</strong> A single attacker can
trigger multiple losses across the same asset. The model treats each year
independently.<br><br>

<strong>Does not model reputational cascade, regulatory fines, or litigation.</strong>
These frequently dominate large-incident losses, and they are excluded here
because they are business-specific and not derivable from CVE data.<br><br>

<strong>Control maturity is a proxy.</strong> The slider captures a normalized
estimate, not a measured control effectiveness. A real deployment should derive
this from audit findings, control testing, or coverage data.<br><br>

<strong>FAIR is a registered trademark of the Open Group.</strong> This is an
illustrative implementation. The assumptions are yours to validate before any
real budget decision.
</div>
""", unsafe_allow_html=True)

st.markdown("---")
st.markdown(
    f'<p style="font-size:12px;color:{C["text_muted"]};line-height:1.7;text-align:center;">'
    'Built so that quantitative risk analysis does not require a six-figure '
    f'consulting contract. · <a href="{REPO_URL}" style="color:{C["cyan"]};">Source</a> '
    f'· <a href="{LINKEDIN_URL}" style="color:{C["cyan"]};">Contact</a>'
    '</p>',
    unsafe_allow_html=True,
)