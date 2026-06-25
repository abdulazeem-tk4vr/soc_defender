from __future__ import annotations

import re
from typing import Any

try:
    from server.models import AgentAction
except ImportError:
    from pydantic import BaseModel, Field

    class AgentAction(BaseModel):
        action_type: str
        params: dict[str, Any] = Field(default_factory=dict)


ALLOWED_ACTIONS = {
    "query_logs",
    "fetch_email",
    "fetch_alert",
    "isolate_host",
    "block_domain",
    "reset_user",
    "submit_report",
}

REPORT_FIELDS = {
    "patient_zero_host",
    "compromised_user",
    "attacker_domain",
    "data_target",
    "initial_vector",
    "containment_actions",
}

TABLE_COLUMNS = {
    "email_logs": {"email_id", "scenario_id", "step", "sender", "recipient", "subject", "body", "is_phish", "injection_id", "trust_tier", "source", "created_at"},
    "auth_logs": {"auth_id", "scenario_id", "step", "user_id", "host_id", "source_ip", "auth_type", "success", "trust_tier", "source", "created_at"},
    "netflow": {"flow_id", "scenario_id", "step", "src_host", "dst_host", "dst_domain", "dst_port", "protocol", "bytes_sent", "bytes_received", "trust_tier", "source", "created_at"},
    "process_events": {"event_id", "scenario_id", "step", "host_id", "user_id", "process_name", "command_line", "parent_process", "trust_tier", "source", "created_at"},
    "alerts": {"alert_id", "scenario_id", "step", "alert_type", "severity", "message", "related_log_id", "injection_id", "trust_tier", "source", "created_at"},
}
ALLOWED_TABLES = set(TABLE_COLUMNS)
SQL_KEYWORDS = {
    "select", "from", "where", "and", "or", "not", "null", "is", "like", "in", "order", "by", "desc", "asc",
    "limit", "as", "distinct", "count", "min", "max", "sum", "avg", "lower", "upper", "cast", "integer",
}
DISALLOWED_SQL_TOKENS = {"now", "current_timestamp", "interval", "date", "datetime", "julianday", "strftime"}


def referenced_tables(sql: str) -> set[str]:
    return {m.group(1).lower() for m in re.finditer(r"\bfrom\s+([a-zA-Z_][a-zA-Z0-9_]*)", sql, re.I)}


def referenced_identifiers(sql: str) -> set[str]:
    scrubbed = re.sub(r"'[^']*(?:''[^']*)*'", " ", sql)
    return {token.lower() for token in re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", scrubbed)}


def is_safe_select(sql: str) -> bool:
    stripped = sql.strip()
    if not stripped.lower().startswith("select"):
        return False
    if ";" in stripped[:-1]:
        return False
    if stripped.rstrip(";").strip().lower() == "select 1":
        return False
    tables = referenced_tables(stripped)
    if not tables or not tables.issubset(ALLOWED_TABLES):
        return False
    identifiers = referenced_identifiers(stripped)
    if identifiers.intersection(DISALLOWED_SQL_TOKENS):
        return False
    allowed_columns = set().union(*(TABLE_COLUMNS[table] for table in tables))
    allowed = allowed_columns | tables | SQL_KEYWORDS
    return identifiers.issubset(allowed)


def make_action(action_type: str, **params: Any) -> AgentAction:
    if action_type not in ALLOWED_ACTIONS:
        return query_logs("SELECT * FROM alerts ORDER BY step DESC LIMIT 20")
    return AgentAction(action_type=action_type, params=params)


def query_logs(sql: str) -> AgentAction:
    return AgentAction(action_type="query_logs", params={"sql": sql})


def fetch_email(email_id: str) -> AgentAction:
    return AgentAction(action_type="fetch_email", params={"email_id": email_id})


def fetch_alert(alert_id: str) -> AgentAction:
    return AgentAction(action_type="fetch_alert", params={"alert_id": alert_id})


def isolate_host(host_id: str) -> AgentAction:
    return AgentAction(action_type="isolate_host", params={"host_id": host_id})


def block_domain(domain: str) -> AgentAction:
    return AgentAction(action_type="block_domain", params={"domain": domain})


def reset_user(user_id: str) -> AgentAction:
    return AgentAction(action_type="reset_user", params={"user_id": user_id})


def submit_report(summary_json: dict[str, Any]) -> AgentAction:
    return AgentAction(action_type="submit_report", params={"summary_json": normalize_report(summary_json)})


def normalize_report(report: dict[str, Any] | None) -> dict[str, Any]:
    report = dict(report or {})
    containment = report.get("containment_actions")
    if not isinstance(containment, dict):
        containment = {}
    normalized = {
        "patient_zero_host": str(report.get("patient_zero_host") or "unknown"),
        "compromised_user": str(report.get("compromised_user") or "unknown"),
        "attacker_domain": str(report.get("attacker_domain") or "unknown"),
        "data_target": str(report.get("data_target") or "unknown"),
        "initial_vector": str(report.get("initial_vector") or "phish"),
        "containment_actions": {
            "isolated_hosts": list(containment.get("isolated_hosts") or []),
            "blocked_domains": list(containment.get("blocked_domains") or []),
            "reset_users": list(containment.get("reset_users") or []),
        },
    }
    return normalized


def validate_action(action: AgentAction) -> tuple[bool, str]:
    if action.action_type not in ALLOWED_ACTIONS:
        return False, "unknown action_type"
    params = action.params or {}
    if action.action_type == "query_logs":
        sql = params.get("sql")
        if not isinstance(sql, str) or not is_safe_select(sql):
            return False, "query_logs requires safe read-only SELECT over evidence tables"
    elif action.action_type == "fetch_email" and not params.get("email_id"):
        return False, "fetch_email requires email_id"
    elif action.action_type == "fetch_alert" and not params.get("alert_id"):
        return False, "fetch_alert requires alert_id"
    elif action.action_type == "isolate_host" and not params.get("host_id"):
        return False, "isolate_host requires host_id"
    elif action.action_type == "block_domain" and not params.get("domain"):
        return False, "block_domain requires domain"
    elif action.action_type == "reset_user" and not params.get("user_id"):
        return False, "reset_user requires user_id"
    elif action.action_type == "submit_report":
        report = params.get("summary_json")
        if not isinstance(report, dict) or not REPORT_FIELDS.issubset(report):
            return False, "submit_report requires complete summary_json"
        containment = report.get("containment_actions")
        if not isinstance(containment, dict):
            return False, "submit_report requires containment_actions object"
        for key in ("isolated_hosts", "blocked_domains", "reset_users"):
            if not isinstance(containment.get(key), list):
                return False, f"submit_report requires containment_actions.{key} list"
    return True, "ok"
