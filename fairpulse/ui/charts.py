"""Plotly chart builders with a consistent FairPulse dark theme."""

from __future__ import annotations

import numpy as np
import plotly.graph_objects as go

from core.fair_model import SimulationResult, loss_exceedance_curve

BG = "rgba(0,0,0,0)"
PANEL = "#0A0E17"
TEXT = "#F5F7FA"
MUTED = "#9AA6B6"
GRID = "#253247"
CYAN = "#00E5FF"
GREEN = "#10B981"
RED = "#EF4444"


def _base_layout(fig: go.Figure, *, height: int = 420) -> go.Figure:
    fig.update_layout(
        template="plotly_dark",
        paper_bgcolor=BG,
        plot_bgcolor=BG,
        font={"family": "Outfit, Inter, Arial, sans-serif", "color": TEXT, "size": 12},
        height=height,
        margin={"l": 16, "r": 20, "t": 40, "b": 18},
        legend={"orientation": "h", "y": 1.12, "x": 0, "font": {"color": MUTED}},
        hoverlabel={"bgcolor": PANEL, "bordercolor": GRID, "font": {"color": TEXT}},
    )
    fig.update_xaxes(gridcolor=GRID, zerolinecolor=GRID, linecolor=GRID, tickfont={"color": MUTED})
    fig.update_yaxes(gridcolor=GRID, zerolinecolor=GRID, linecolor=GRID, tickfont={"color": MUTED})
    return fig


def loss_exceedance_figure(result: SimulationResult) -> go.Figure:
    current_x, current_y = loss_exceedance_curve(result.current_losses)
    target_x, target_y = loss_exceedance_curve(result.target_losses)

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=current_x, y=current_y, mode="lines", name="Current state",
        line={"color": CYAN, "width": 2.4},
        hovertemplate="Annual loss: %{x:,.0f}<br>Exceedance probability: %{y:.1%}<extra>Current</extra>",
    ))
    fig.add_trace(go.Scatter(
        x=target_x, y=target_y, mode="lines", name="Proposed state",
        line={"color": GREEN, "width": 2.4},
        hovertemplate="Annual loss: %{x:,.0f}<br>Exceedance probability: %{y:.1%}<extra>Proposed</extra>",
    ))
    fig.update_layout(title="Annual loss exceedance", xaxis_title=f"Annual aggregate loss ({result.scenario.currency})", yaxis_title="Probability of exceeding loss")
    fig.update_yaxes(tickformat=".0%", range=[0, 1])
    return _base_layout(fig, height=470)


def loss_distribution_figure(result: SimulationResult) -> go.Figure:
    fig = go.Figure()
    fig.add_trace(go.Histogram(
        x=result.current_losses,
        name="Current state",
        opacity=0.62,
        marker_color=CYAN,
        nbinsx=55,
        histnorm="probability density",
        hovertemplate="Loss: %{x:,.0f}<br>Density: %{y:.5f}<extra>Current</extra>",
    ))
    fig.add_trace(go.Histogram(
        x=result.target_losses,
        name="Proposed state",
        opacity=0.58,
        marker_color=GREEN,
        nbinsx=55,
        histnorm="probability density",
        hovertemplate="Loss: %{x:,.0f}<br>Density: %{y:.5f}<extra>Proposed</extra>",
    ))
    fig.update_layout(
        title="Simulated annual aggregate loss distribution",
        xaxis_title=f"Annual aggregate loss ({result.scenario.currency})",
        yaxis_title="Probability density",
        barmode="overlay",
    )
    return _base_layout(fig, height=420)


def roi_bridge_figure(result: SimulationResult) -> go.Figure:
    labels = ["Current ALE", "Proposed ALE", "Risk reduction", "Annualised mitigation cost"]
    values = [
        result.current_ale,
        result.target_ale,
        result.risk_reduction,
        result.annualised_mitigation_cost,
    ]
    colors = [CYAN, GREEN, GREEN if result.risk_reduction >= 0 else RED, RED]
    fig = go.Figure(go.Bar(
        x=labels,
        y=values,
        marker_color=colors,
        text=[f"{v:,.0f}" for v in values],
        textposition="auto",
        hovertemplate="%{x}<br>%{y:,.2f}<extra></extra>",
    ))
    fig.update_layout(title="Annual financial comparison", yaxis_title=f"Amount ({result.scenario.currency})", showlegend=False)
    fig.update_xaxes(tickangle=-10)
    return _base_layout(fig, height=370)


def percentile_comparison_figure(result: SimulationResult) -> go.Figure:
    keys = ["p50", "p75", "p90", "p95", "p99"]
    labels = ["P50", "P75", "P90", "P95", "P99"]
    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=labels,
        y=[result.current_percentiles[k] for k in keys],
        name="Current state", marker_color=CYAN,
        hovertemplate="%{x}: %{y:,.0f}<extra>Current</extra>",
    ))
    fig.add_trace(go.Bar(
        x=labels,
        y=[result.target_percentiles[k] for k in keys],
        name="Proposed state", marker_color=GREEN,
        hovertemplate="%{x}: %{y:,.0f}<extra>Proposed</extra>",
    ))
    fig.update_layout(title="Annual loss percentiles", barmode="group", yaxis_title=f"Annual loss ({result.scenario.currency})")
    return _base_layout(fig, height=370)
