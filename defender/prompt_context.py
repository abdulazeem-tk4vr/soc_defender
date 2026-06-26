from __future__ import annotations

from typing import Any


def report_gaps(report_values: dict[str, str] | None) -> list[str]:
    values = report_values or {}
    return [key for key, value in values.items() if value == "unknown"]


def gap_terms(gaps: list[str]) -> str:
    terms = []
    if "attacker_domain" in gaps:
        terms.append("identify attacker domain phishing email headers netflow dst_domain exfiltration")
    if "data_target" in gaps:
        terms.append("identify data target staging exfiltration process_events file access")
    if "patient_zero_host" in gaps:
        terms.append("identify patient zero host credential theft authentication alerts")
    if "compromised_user" in gaps:
        terms.append("identify compromised user phishing credential reuse authentication")
    if not terms:
        terms.append("containment evidence isolate host reset user block domain")
    return " ".join(terms)


def report_focus(report_values: dict[str, str] | None) -> dict[str, Any]:
    gaps = report_gaps(report_values)
    return {
        "unknown_report_fields": gaps,
        "gap_terms": gap_terms(gaps),
    }
