import pytest

from integrations.threat_intel import parse_epss_payload, parse_kev_payload, validate_cve_id


def test_cve_validation_normalises_case():
    assert validate_cve_id("cve-2024-3400") == "CVE-2024-3400"


def test_cve_validation_rejects_invalid_identifier():
    with pytest.raises(ValueError):
        validate_cve_id("not-a-cve")


def test_parse_epss_payload_extracts_probability_and_percentile():
    payload = {"data": [{"cve": "CVE-2024-3400", "epss": "0.42", "percentile": "0.91", "date": "2026-11-01"}]}
    row = parse_epss_payload(payload, "CVE-2024-3400")
    assert row is not None
    assert row["epss"] == pytest.approx(0.42)
    assert row["percentile"] == pytest.approx(0.91)


def test_parse_epss_no_match_returns_none_not_zero():
    assert parse_epss_payload({"data": []}, "CVE-2024-3400") is None


def test_parse_kev_payload_returns_matching_entry():
    payload = {
        "catalogVersion": "2026.10",
        "dateReleased": "2026-10-30",
        "vulnerabilities": [{
            "cveID": "CVE-2024-3400",
            "vendorProject": "Vendor",
            "product": "Product",
            "dateAdded": "2024-04-12",
            "dueDate": "2024-04-26",
            "knownRansomwareCampaignUse": "Unknown",
        }],
    }
    row = parse_kev_payload(payload, "CVE-2024-3400")
    assert row is not None and row["listed"] is True
    assert row["vendor_project"] == "Vendor"


def test_parse_kev_catalogue_absence_is_explicit():
    row = parse_kev_payload({"vulnerabilities": []}, "CVE-2024-3400")
    assert row == {"listed": False, "cve": "CVE-2024-3400", "catalog_version": None, "catalog_date_released": None, "retrieved_at": row["retrieved_at"]}
