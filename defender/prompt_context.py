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


def objective_query_guidance(report_values: dict[str, str] | None) -> list[dict[str, Any]]:
    values = report_values or {}
    known_hosts = [value for key, value in values.items() if key == "patient_zero_host" and value != "unknown"]
    known_users = [value for key, value in values.items() if key == "compromised_user" and value != "unknown"]
    return [
        {
            "objective": "find_identity",
            "preferred_sources": ["email_logs", "auth_logs", "alerts"],
            "look_for": ["user_id", "user", "recipient", "phishing or credential indicators"],
            "template": "fetch new email IDs first; otherwise query auth_logs/email_logs for user evidence",
            "known_entities": {"users": known_users},
        },
        {
            "objective": "find_patient_zero",
            "preferred_sources": ["auth_logs", "alerts", "process_events"],
            "look_for": ["host_id", "host", "src_host", "credential or alert indicators"],
            "template": "query auth_logs/alerts/process_events for the first trusted host tied to the compromised user",
            "known_entities": {"users": known_users, "hosts": known_hosts},
        },
        {
            "objective": "find_attacker_domain",
            "preferred_sources": ["alerts", "netflow", "email_logs"],
            "look_for": ["dst_domain", "destination_domain", "domain", "exfiltration indicators"],
            "template": "query alerts/netflow and inspect dst_domain specifically; do not use SMTP-port-only filters unless dst_domain is selected",
            "known_entities": {"hosts": known_hosts, "users": known_users},
        },
        {
            "objective": "find_data_target",
            "preferred_sources": ["process_events", "alerts"],
            "look_for": ["target_id", "data_target", "target=", "stage or exfil commands"],
            "template": "query process_events and inspect target/data_target fields or target= tokens in command/template text",
            "known_entities": {"hosts": known_hosts, "users": known_users},
        },
        {
            "objective": "corroborate_containment",
            "preferred_sources": ["alerts", "auth_logs", "netflow", "process_events"],
            "look_for": ["trusted support for known host/user/domain"],
            "template": "only corroborate after critical report fields are known",
            "known_entities": {"hosts": known_hosts, "users": known_users},
        },
    ]


def exhausted_query_guidance(emitted_counts: dict[str, int] | None, failed_queries: set[str] | None = None) -> list[dict[str, Any]]:
    failed = failed_queries or set()
    exhausted = []
    for sql, count in sorted((emitted_counts or {}).items(), key=lambda item: (-item[1], item[0])):
        if count < 2 and sql not in failed:
            continue
        exhausted.append({"sql": sql, "attempts": count, "failed": sql in failed, "guidance": "avoid repeating; pivot source or objective template"})
    return exhausted[:8]
