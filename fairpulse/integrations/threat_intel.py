"""Public threat-intelligence adapters for FIRST EPSS and CISA KEV."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

import requests

EPSS_URL = "https://api.first.org/data/v1/epss"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
USER_AGENT = "FairPulse-CRQ-Portfolio/1.0"


class ThreatIntelError(RuntimeError):
    """Raised when a public threat-intelligence source cannot be retrieved."""


def validate_cve_id(cve_id: str) -> str:
    cleaned = (cve_id or "").strip().upper()
    if not CVE_PATTERN.fullmatch(cleaned):
        raise ValueError("Enter a valid CVE identifier, for example CVE-2024-3400.")
    return cleaned


def _get_json(url: str, *, params: dict[str, str] | None = None, timeout: float = 10.0) -> dict[str, Any]:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    try:
        response = requests.get(url, params=params, headers=headers, timeout=timeout)
        response.raise_for_status()
        payload = response.json()
    except requests.Timeout as exc:
        raise ThreatIntelError(f"Request timed out while contacting {url.split('/')[2]}.") from exc
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else "unknown"
        raise ThreatIntelError(f"Source returned HTTP {status}.") from exc
    except requests.RequestException as exc:
        raise ThreatIntelError(f"Could not connect to {url.split('/')[2]}.") from exc
    except ValueError as exc:
        raise ThreatIntelError("Source returned invalid JSON.") from exc

    if not isinstance(payload, dict):
        raise ThreatIntelError("Source returned an unexpected response format.")
    return payload


def parse_epss_payload(payload: dict[str, Any], cve_id: str) -> dict[str, Any] | None:
    """Extract one CVE's EPSS record without assuming a record exists."""
    data = payload.get("data", [])
    if not isinstance(data, list):
        raise ThreatIntelError("EPSS response did not contain a data list.")
    wanted = validate_cve_id(cve_id)
    for row in data:
        if isinstance(row, dict) and str(row.get("cve", "")).upper() == wanted:
            try:
                score = float(row["epss"])
                percentile = float(row["percentile"])
            except (KeyError, TypeError, ValueError) as exc:
                raise ThreatIntelError("EPSS returned an invalid score for this CVE.") from exc
            if not 0 <= score <= 1 or not 0 <= percentile <= 1:
                raise ThreatIntelError("EPSS returned a score outside the expected 0–1 range.")
            return {
                "cve": wanted,
                "epss": score,
                "percentile": percentile,
                "date": row.get("date") or row.get("created"),
                "retrieved_at": datetime.now(timezone.utc).isoformat(),
            }
    return None


def fetch_epss(cve_id: str, *, timeout: float = 10.0) -> dict[str, Any] | None:
    cve = validate_cve_id(cve_id)
    payload = _get_json(EPSS_URL, params={"cve": cve}, timeout=timeout)
    return parse_epss_payload(payload, cve)


def parse_kev_payload(payload: dict[str, Any], cve_id: str) -> dict[str, Any] | None:
    """Find a CVE in the CISA KEV catalogue and return source metadata."""
    vulnerabilities = payload.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise ThreatIntelError("CISA KEV response did not contain a vulnerabilities list.")
    wanted = validate_cve_id(cve_id)
    for row in vulnerabilities:
        if isinstance(row, dict) and str(row.get("cveID", "")).upper() == wanted:
            return {
                "listed": True,
                "cve": wanted,
                "vendor_project": row.get("vendorProject"),
                "product": row.get("product"),
                "vulnerability_name": row.get("vulnerabilityName"),
                "date_added": row.get("dateAdded"),
                "due_date": row.get("dueDate"),
                "known_ransomware_campaign_use": row.get("knownRansomwareCampaignUse"),
                "required_action": row.get("requiredAction"),
                "catalog_version": payload.get("catalogVersion"),
                "catalog_date_released": payload.get("dateReleased"),
                "retrieved_at": datetime.now(timezone.utc).isoformat(),
            }
    return {
        "listed": False,
        "cve": wanted,
        "catalog_version": payload.get("catalogVersion"),
        "catalog_date_released": payload.get("dateReleased"),
        "retrieved_at": datetime.now(timezone.utc).isoformat(),
    }


def fetch_kev_catalog(*, timeout: float = 15.0) -> dict[str, Any]:
    return _get_json(CISA_KEV_URL, timeout=timeout)


def lookup_kev(cve_id: str, catalog_payload: dict[str, Any]) -> dict[str, Any] | None:
    return parse_kev_payload(catalog_payload, cve_id)
