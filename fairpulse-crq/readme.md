# FairPulse — Cyber risk, quantified

A single-file Streamlit application that converts one CVE into a
board-legible financial decision using FAIR-aligned Monte Carlo simulation
on live FIRST.org and CISA telemetry.

**Live app:** https://fairpulse.streamlit.app
**Author:** Your Name · [LinkedIn](https://www.linkedin.com/in/you/)

## What it does

1. Takes a CVE ID and an asset valuation as input.
2. Fetches live exploit probability from FIRST EPSS and checks the CISA
   Known Exploited Vulnerabilities catalog at request time.
3. Runs 10,000 Monte Carlo iterations using a FAIR decomposition
   (Triangular TEF × Poisson LEF × Triangular SLE) to produce an
   annualized loss distribution.
4. Runs a second simulation at the proposed control maturity to compute
   Return on Security Investment.
5. Maps each FAIR factor to the specific EU DORA, NIS2, ISO 27001:2022,
   and NIST CSF 2.0 clauses it evidences.

## What it does not do

See the "Limits" section in the app. The model is a prioritization tool,
not a loss forecast. It does not model correlated loss events, reputational
cascade, regulatory fines, or litigation. Control maturity is a normalized
proxy, not a measured effectiveness.

## Run locally

```bash
pip install streamlit requests numpy plotly
streamlit run app.py