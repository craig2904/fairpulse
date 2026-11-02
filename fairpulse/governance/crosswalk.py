"""Curated, high-level governance crosswalk used by the FairPulse demo.

These are indicative relationships to public requirements / control labels,
not a legal opinion, complete implementation guide, or compliance assessment.
"""

from __future__ import annotations

MAPPINGS = [
    {
        "framework": "EU DORA",
        "reference": "Regulation (EU) 2022/2554 — Article 6",
        "title": "ICT risk management framework",
        "relevance": "The model supports risk analysis by structuring threat frequency, vulnerability, loss magnitude and mitigation assumptions into a documented scenario.",
        "evidence_to_retain": "Approved risk assessment, documented assumptions, asset owner, risk appetite decision and treatment decision.",
        "url": "https://eur-lex.europa.eu/eli/reg/2022/2554/oj",
        "topics": ["Risk analysis", "Governance", "Financial exposure"],
    },
    {
        "framework": "EU DORA",
        "reference": "Regulation (EU) 2022/2554 — Article 8",
        "title": "Identification",
        "relevance": "The scenario links an ICT vulnerability to an information or ICT asset and documents a risk scenario that may affect a supported business function.",
        "evidence_to_retain": "Asset inventory, affected system/version validation, dependency mapping and risk-scenario review.",
        "url": "https://eur-lex.europa.eu/eli/reg/2022/2554/oj",
        "topics": ["Vulnerability management", "Asset exposure", "Risk analysis"],
    },
    {
        "framework": "EU DORA",
        "reference": "Regulation (EU) 2022/2554 — Article 9",
        "title": "Protection and prevention",
        "relevance": "Mitigation modelling can inform discussion of protective measures and the expected effect of a proposed control change.",
        "evidence_to_retain": "Control design, implementation evidence, vulnerability remediation records and effectiveness testing.",
        "url": "https://eur-lex.europa.eu/eli/reg/2022/2554/oj",
        "topics": ["Vulnerability management", "Mitigation", "Control effectiveness"],
    },
    {
        "framework": "EU DORA",
        "reference": "Regulation (EU) 2022/2554 — Article 11",
        "title": "Response and recovery",
        "relevance": "Primary and secondary loss assumptions can help frame business-continuity, response and recovery cost scenarios.",
        "evidence_to_retain": "Business impact analysis, continuity plans, recovery objectives and test results.",
        "url": "https://eur-lex.europa.eu/eli/reg/2022/2554/oj",
        "topics": ["Business continuity", "Loss magnitude", "Recovery"],
    },
    {
        "framework": "NIS2",
        "reference": "Directive (EU) 2022/2555 — Article 21",
        "title": "Cybersecurity risk-management measures",
        "relevance": "The vulnerability scenario can support risk analysis and discussion of vulnerability handling, incident handling, business continuity and proportionate controls.",
        "evidence_to_retain": "Risk-analysis policy, vulnerability-handling process, remediation records, control-owner approvals and continuity evidence.",
        "url": "https://eur-lex.europa.eu/eli/dir/2022/2555/oj",
        "topics": ["Risk analysis", "Vulnerability management", "Mitigation", "Business continuity"],
    },
    {
        "framework": "NIS2",
        "reference": "Directive (EU) 2022/2555 — Article 23",
        "title": "Reporting obligations",
        "relevance": "This is incident-reporting context if a cyber incident occurs; a pre-incident CVE risk simulation does not itself trigger or satisfy reporting obligations.",
        "evidence_to_retain": "Incident classification, detection timeline, incident records and applicable reporting decision log.",
        "url": "https://eur-lex.europa.eu/eli/dir/2022/2555/oj",
        "topics": ["Incident response", "Incident reporting"],
    },
    {
        "framework": "ISO/IEC 27001:2022",
        "reference": "Annex A — A.5.7",
        "title": "Threat intelligence",
        "relevance": "FIRST EPSS and CISA KEV are examples of external threat information that an organisation may collect, analyse and use as inputs to risk assessment.",
        "evidence_to_retain": "Threat-intelligence source register, analysis records, dates, relevance assessment and decisions taken.",
        "url": "https://www.iso.org/standard/27001",
        "topics": ["Threat intelligence", "Risk analysis"],
    },
    {
        "framework": "ISO/IEC 27001:2022",
        "reference": "Annex A — A.8.8",
        "title": "Management of technical vulnerabilities",
        "relevance": "The CVE scenario supports analysis of technical vulnerability exposure and the evaluation of appropriate remediation actions.",
        "evidence_to_retain": "Vulnerability records, affected-asset validation, risk-based prioritisation, remediation and verification evidence.",
        "url": "https://www.iso.org/standard/27001",
        "topics": ["Vulnerability management", "Threat intelligence", "Mitigation"],
    },
    {
        "framework": "ISO/IEC 27001:2022",
        "reference": "Annex A — A.5.9",
        "title": "Inventory of information and other associated assets",
        "relevance": "The asset-value input should be traceable to an identified asset and an approved business owner rather than treated as a stand-alone estimate.",
        "evidence_to_retain": "Asset inventory, ownership, classification and valuation rationale.",
        "url": "https://www.iso.org/standard/27001",
        "topics": ["Asset exposure", "Risk analysis"],
    },
]


def all_mappings() -> list[dict[str, object]]:
    return list(MAPPINGS)
