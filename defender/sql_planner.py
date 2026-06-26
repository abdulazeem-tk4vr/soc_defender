from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .actions import is_safe_select, query_logs


def quote_sql(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


@dataclass
class SQLPlanner:
    failed_queries: set[str] = field(default_factory=set)
    emitted_queries: set[str] = field(default_factory=set)
    emitted_counts: dict[str, int] = field(default_factory=dict)
    last_emitted_sql: str | None = None
    query_history: list[dict[str, Any]] = field(default_factory=list)

    def record_failure(self, sql: str) -> None:
        self.failed_queries.add(sql.strip())

    def record_result(self, sql: str, rows_returned: int, ok: bool = True) -> None:
        meta = describe_sql(sql)
        self.query_history.append({
            "sql": sql.strip(),
            "entity": meta.get("entity"),
            "log_type": meta.get("log_type"),
            "rows_returned": rows_returned,
            "ok": ok,
        })

    def compact_history(self, limit: int = 12) -> list[dict[str, Any]]:
        return [
            {key: value for key, value in item.items() if key != "sql"}
            for item in self.query_history[-limit:]
        ]

    def tried_approaches(self, limit: int = 12) -> list[str]:
        approaches = []
        for item in self.query_history[-limit:]:
            entity = item.get("entity") or "broad"
            log_type = item.get("log_type") or "unknown"
            rows = item.get("rows_returned", 0)
            approaches.append(f"query_logs {entity} {log_type}: {rows} rows")
        return approaches

    def already_emitted(self, sql: str) -> bool:
        return sql.strip() in self.emitted_queries

    def action_for_sql(self, sql: str):
        sql = self.repair(sql)
        self.emitted_queries.add(sql)
        self.emitted_counts[sql] = self.emitted_counts.get(sql, 0) + 1
        self.last_emitted_sql = sql
        return query_logs(sql)

    def repair(self, sql: str) -> str:
        sql = sql.strip()
        if is_safe_select(sql) and sql not in self.failed_queries and not self.already_emitted(sql):
            return sql
        return self.next_broad_query()

    def next_broad_query(self, report_gaps: set[str] | None = None):
        report_gaps = report_gaps or set()
        candidates = self._broad_candidates(report_gaps)
        for sql in candidates:
            if sql not in self.failed_queries and not self.already_emitted(sql):
                return sql
        available = [sql for sql in candidates if sql not in self.failed_queries]
        if available:
            return min(available, key=lambda sql: self.emitted_counts.get(sql, 0))
        return "SELECT * FROM alerts ORDER BY step DESC LIMIT 20"

    @staticmethod
    def _broad_candidates(report_gaps: set[str]) -> list[str]:
        default = [
            "SELECT * FROM alerts ORDER BY step DESC LIMIT 20",
            "SELECT * FROM email_logs ORDER BY step DESC LIMIT 20",
            "SELECT * FROM auth_logs ORDER BY step DESC LIMIT 20",
            "SELECT * FROM netflow ORDER BY step DESC LIMIT 20",
            "SELECT * FROM process_events ORDER BY step DESC LIMIT 20",
        ]
        if "attacker_domain" in report_gaps and "data_target" in report_gaps:
            return [
                "SELECT * FROM netflow ORDER BY step DESC LIMIT 20",
                "SELECT * FROM process_events ORDER BY step DESC LIMIT 20",
                "SELECT * FROM alerts ORDER BY step DESC LIMIT 20",
                "SELECT * FROM email_logs ORDER BY step DESC LIMIT 20",
                "SELECT * FROM auth_logs ORDER BY step DESC LIMIT 20",
            ]
        if "attacker_domain" in report_gaps:
            return [
                "SELECT * FROM netflow ORDER BY step DESC LIMIT 20",
                "SELECT * FROM alerts ORDER BY step DESC LIMIT 20",
                "SELECT * FROM email_logs ORDER BY step DESC LIMIT 20",
                "SELECT * FROM process_events ORDER BY step DESC LIMIT 20",
                "SELECT * FROM auth_logs ORDER BY step DESC LIMIT 20",
            ]
        if "data_target" in report_gaps:
            return [
                "SELECT * FROM process_events ORDER BY step DESC LIMIT 20",
                "SELECT * FROM alerts ORDER BY step DESC LIMIT 20",
                "SELECT * FROM netflow ORDER BY step DESC LIMIT 20",
                "SELECT * FROM email_logs ORDER BY step DESC LIMIT 20",
                "SELECT * FROM auth_logs ORDER BY step DESC LIMIT 20",
            ]
        return default

    def query_for_entity(self, entity_value: str, entity_type: str, report_gaps: set[str] | None = None):
        value = quote_sql(entity_value)
        report_gaps = report_gaps or set()
        if entity_type == "host":
            candidates = []
            if "attacker_domain" in report_gaps:
                candidates.append(f"SELECT * FROM netflow WHERE src_host = {value} ORDER BY step DESC LIMIT 20")
                candidates.append(f"SELECT * FROM netflow WHERE host_id = {value} ORDER BY step DESC LIMIT 20")
            if "data_target" in report_gaps:
                candidates.append(f"SELECT * FROM process_events WHERE host_id = {value} ORDER BY step DESC LIMIT 20")
            candidates.append(f"SELECT * FROM auth_logs WHERE host_id = {value} ORDER BY step DESC LIMIT 20")
            return self.action_for_sql(self._first_available(candidates))
        if entity_type == "user":
            candidates = []
            if "data_target" in report_gaps:
                candidates.append(f"SELECT * FROM process_events WHERE user_id = {value} ORDER BY step DESC LIMIT 20")
            candidates.append(f"SELECT * FROM auth_logs WHERE user_id = {value} ORDER BY step DESC LIMIT 20")
            candidates.append(f"SELECT * FROM alerts WHERE message LIKE {quote_sql('%' + entity_value + '%')} ORDER BY step DESC LIMIT 20")
            return self.action_for_sql(self._first_available(candidates))
        if entity_type == "domain":
            return self.action_for_sql(
                "SELECT * FROM netflow WHERE dst_domain = "
                f"{value} ORDER BY step DESC LIMIT 20"
            )
        if entity_type == "target":
            return self.action_for_sql(
                "SELECT * FROM process_events WHERE target_id = "
                f"{value} ORDER BY step DESC LIMIT 20"
            )
        return self.action_for_sql(f"SELECT * FROM alerts WHERE message LIKE {quote_sql('%' + entity_value + '%')} ORDER BY step DESC LIMIT 20")

    def _first_available(self, candidates: list[str]) -> str:
        for sql in candidates:
            if sql not in self.failed_queries and not self.already_emitted(sql):
                return sql
        return candidates[0] if candidates else self.next_broad_query()


def describe_sql(sql: str) -> dict[str, str | None]:
    table_match = re.search(r"\bFROM\s+([A-Za-z_][A-Za-z0-9_]*)", sql, re.I)
    entity_match = re.search(r"\b(?:host_id|src_host|dst_host|user_id|dst_domain|target_id)\s*=\s*'([^']+)'", sql, re.I)
    return {
        "log_type": table_match.group(1) if table_match else None,
        "entity": entity_match.group(1) if entity_match else None,
    }
