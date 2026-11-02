# FairPulse — Cyber Risk Quantification

An open-source portfolio application demonstrating how vulnerability intelligence and analyst-defined risk assumptions can be translated into a **FAIR-informed financial loss distribution** using Monte Carlo simulation.

> **Important:** FairPulse is a decision-support demonstration, not a certified FAIR implementation, audited risk model, legal opinion, compliance assessment or guaranteed forecast. Results are conditional on user-entered assumptions. Calibrate the model with organisation-specific data before any operational use.

## What it does

- Looks up a CVE's current EPSS record from the public FIRST.org API.
- Checks the CISA Known Exploited Vulnerabilities (KEV) catalogue.
- Runs a configurable Monte Carlo simulation (10,000 iterations by default).
- Estimates current-state and proposed-state Annualized Loss Expectancy (ALE).
- Produces an interactive Loss Exceedance Curve (LEC) and loss percentiles.
- Calculates a mitigation ROI using a transparent straight-line annualisation of one-off cost plus annual operating cost.
- Shows an indicative crosswalk to selected DORA, NIS2 and ISO/IEC 27001:2022 references.
- Exports scenario assumptions and results to JSON and CSV.

## Four application views

1. **Risk Overview** — executive metrics, threat intelligence and an automated CISO action summary.
2. **Loss Distribution** — LEC, simulated annual loss distribution and loss percentiles.
3. **Mitigation ROI** — current versus proposed state, annualised cost, net benefit, ROSI and simple payback.
4. **Governance** — indicative DORA, NIS2 and ISO/IEC 27001 crosswalk plus methodology and limitations.

Scenario inputs are grouped in the sidebar and submitted through a Streamlit form. The Monte Carlo model does not execute on each slider change.

## Model design

### 1. Threat and vulnerability assumptions

The analyst supplies a triangular distribution for annual Threat Event Frequency (TEF), in events per year, and a triangular distribution for base susceptibility, expressed as a probability per threat event. TEF is entered as a combined annual event-frequency assumption; the app does not separately elicit contact frequency and probability of action.

### 2. Control-maturity calibration

The application asks for current and proposed control maturity (0–100) and a configurable maximum effectiveness at 100% maturity. The model maps these inputs as:

```text
control_effectiveness = (control_maturity / 100) × max_effectiveness_at_full_maturity
modelled_susceptibility = base_susceptibility × (1 - control_effectiveness)
loss_event_frequency = TEF × modelled_susceptibility
```

This linear maturity-to-effectiveness mapping is a **transparent analyst-selected calibration**, not a conversion mandated by FAIR. Maturity is not inherently the same thing as effectiveness. Replace this mapping with an evidence-based control-effectiveness model before operational use.

### 3. Loss magnitude and annual aggregation

For each simulated year, FairPulse draws a Poisson-distributed count of loss events using the modelled annual loss-event frequency. Each event receives separately sampled primary and secondary loss severity from analyst-specified triangular distributions. Annual aggregate loss is the sum of event severities.

```text
annual_aggregate_loss = Σ(primary_loss_event + secondary_loss_event)
ALE = mean(simulated_annual_aggregate_losses)
```

The triangular ranges, Poisson event process and independence assumptions are modelling choices. They must be challenged and calibrated for the use case.

### 4. Current and target state

The model uses the same sampled TEF and base-susceptibility draws for current and proposed states. Current and proposed control-effectiveness assumptions alter the modelled loss-event frequency. The model separately simulates annual loss outcomes for the two states.

### 5. Mitigation ROI

All financial inputs and outputs use the selected currency label; the app does not perform foreign-exchange conversion. The asset value is shown as contextual exposure and the P95 comparison, but it is not used as a loss cap.

The application annualises the one-off cost on a straight-line basis over the useful life and adds annual operating cost:

```text
annualised_mitigation_cost = upfront_cost / useful_life_years + annual_operating_cost
risk_reduction = current_ALE - target_ALE
net_annual_benefit = risk_reduction - annualised_mitigation_cost
net_ROSI = (net_annual_benefit / annualised_mitigation_cost) × 100
```

ROSI is shown as N/A when annualised cost is zero. Simple payback is calculated only where annual risk reduction after recurring operating cost is positive. The model does not discount cash flows or model tax, insurance recoveries or non-financial benefits.

## How EPSS and KEV are used

- **EPSS:** FIRST describes EPSS as the estimated probability that a published vulnerability will be exploited in the wild in the next 30 days. FairPulse displays the score, percentile and source date.
- **CISA KEV:** The application checks whether the CVE appears in the retrieved KEV catalogue and displays catalogue metadata.
- **No false conversion:** EPSS is not treated as an organisation-specific annual attack frequency, and KEV membership is not treated as a numeric probability multiplier. Analysts should use these signals, together with exposure and threat context, to justify the TEF and susceptibility ranges they enter.
- A missing EPSS record is not converted to zero. If a source is unavailable, the app displays an error and still permits a scenario run using manual assumptions.

## Regulatory mapping boundaries

The Governance view contains selected high-level relationships, including DORA Articles 6, 8, 9 and 11; NIS2 Articles 21 and 23; and ISO/IEC 27001:2022 Annex A controls A.5.7, A.5.9 and A.8.8. The crosswalk is indicative only. It is not exhaustive, does not establish an entity's scope, does not interpret national transposition and does not demonstrate compliance.

## Run locally

Requires Python 3.11 (or a compatible Python version satisfying the dependencies).

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
cd YOUR_REPOSITORY
python -m venv .venv

# macOS / Linux
source .venv/bin/activate

# Windows PowerShell
# .venv\Scripts\Activate.ps1

pip install -r requirements.txt
streamlit run app.py
```

The application does not require API keys for the public FIRST EPSS or CISA KEV sources.

## Configure GitHub and LinkedIn links

Create `.streamlit/secrets.toml` locally by copying `.streamlit/secrets.toml.example`, then add the real URLs:

```toml
[links]
github_url = "https://github.com/your-actual-account/your-actual-repository"
linkedin_url = "https://www.linkedin.com/in/your-actual-profile/"
```

Alternatively set these environment variables:

```text
FAIRPULSE_GITHUB_URL=https://github.com/your-actual-account/your-actual-repository
FAIRPULSE_LINKEDIN_URL=https://www.linkedin.com/in/your-actual-profile/
```

The application deliberately does not invent profile URLs. If links have not been configured, the header shows disabled link controls.

## Deploy to Streamlit Community Cloud

1. Push the complete project folder to a GitHub repository.
2. Open Streamlit Community Cloud and create a new app from that repository.
3. Set the main file path to `app.py`.
4. Select Python 3.11 if the deployment settings offer a version selector.
5. Add the `[links]` entries from `.streamlit/secrets.toml.example` in the app's Secrets settings.
6. Deploy and verify the EPSS request, CISA catalogue retrieval, one completed simulation, chart rendering and JSON/CSV downloads.

No sign-in, database, payment, appointment or persistence integration is included. Simulation inputs and results are held in the active Streamlit session.

## Tests

```bash
pytest -q
```

Tests cover deterministic simulation behaviour, current/target loss direction, ROSI calculations, invalid distributions, the LEC's empirical exceedance values and parsing of representative EPSS/KEV responses. The tests do not make live network requests.

## Performance notes

- EPSS CVE responses and the CISA KEV catalogue are cached for one hour using `st.cache_data`.
- The scenario form prevents recalculation on every widget edit.
- The Monte Carlo model uses NumPy arrays and chunked compound-Poisson severity sampling.
- Do not reduce iteration count or simplify the loss distribution solely to improve speed without measuring runtime and regression-testing outputs.

## Known limitations / next validation steps

- Validate the maturity-to-effectiveness calibration with observed control evidence.
- Validate TEF, susceptibility and loss distributions with subject-matter experts and historical/internal data.
- Consider correlated loss components, changing event rates, common-cause failure, recovery distributions, insurance and discounting if required by the use case.
- Reconcile the implementation with the FAIR taxonomy and your intended FAIR method before describing it as a formal FAIR implementation.
- Regulatory mappings require ongoing review against authoritative texts, guidance and national implementation.
- Live API availability and latency depend on FIRST.org, CISA.gov and the hosting environment.

## Source references

- FIRST EPSS API: <https://api.first.org/epss/>
- CISA KEV catalogue: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>
- FAIR Institute: <https://www.fairinstitute.org/>
- DORA — Regulation (EU) 2022/2554: <https://eur-lex.europa.eu/eli/reg/2022/2554/oj>
- NIS2 — Directive (EU) 2022/2555: <https://eur-lex.europa.eu/eli/dir/2022/2555/oj>
- ISO/IEC 27001: <https://www.iso.org/standard/27001>

---

**Portfolio project:** FairPulse demonstrates transparent, assumption-led cyber-risk quantification. It should not be used as the sole basis for a real security investment, regulatory or risk-acceptance decision.
