from __future__ import annotations

import re
from dataclasses import dataclass, field

from .actions import is_safe_select, query_logs


def quote_sql(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


BROAD_QUERY_TEMPLATES = (
    "SELECT * FROM alerts ORDER BY step DESC LIMIT 20",
    "SELECT * FROM email_logs ORDER BY step DESC LIMIT 20",
    "SELECT * FROM auth_logs ORDER BY step DESC LIMIT 20",
    "SELECT * FROM netflow ORDER BY step DESC LIMIT 20",
    "SELECT * FROM process_events ORDER BY step DESC LIMIT 20",
)

ENTITY_QUERY_PATTERNS = (
    re.compile(r"^SELECT \* FROM auth_logs WHERE host_id = '[^']*(?:''[^']*)*' ORDER BY step DESC LIMIT 20$"),
    re.compile(r"^SELECT \* FROM auth_logs WHERE user_id = '[^']*(?:''[^']*)*' ORDER BY step DESC LIMIT 20$"),
    re.compile(r"^SELECT \* FROM netflow WHERE dst_domain = '[^']*(?:''[^']*)*' ORDER BY step DESC LIMIT 20$"),
    re.compile(r"^SELECT \* FROM process_events WHERE target_id = '[^']*(?:''[^']*)*' ORDER BY step DESC LIMIT 20$"),
)


def is_allowlisted_template(sql: str) -> bool:
    sql = sql.strip()
    return sql in BROAD_QUERY_TEMPLATES or any(pattern.match(sql) for pattern in ENTITY_QUERY_PATTERNS)


@dataclass
class SQLPlanner:
    failed_queries: set[str] = field(default_factory=set)
    emitted_queries: set[str] = field(default_factory=set)
    emitted_counts: dict[str, int] = field(default_factory=dict)
    last_emitted_sql: str | None = None

    def record_failure(self, sql: str) -> None:
        self.failed_queries.add(sql.strip())

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
        if is_safe_select(sql) and is_allowlisted_template(sql) and sql not in self.failed_queries and not self.already_emitted(sql):
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
        default = list(BROAD_QUERY_TEMPLATES)
        if "attacker_domain" in report_gaps:
            return [
                "SELECT * FROM netflow ORDER BY step DESC LIMIT 20",
                "SELECT * FROM email_logs ORDER BY step DESC LIMIT 20",
                "SELECT * FROM alerts ORDER BY step DESC LIMIT 20",
                "SELECT * FROM process_events ORDER BY step DESC LIMIT 20",
                "SELECT * FROM auth_logs ORDER BY step DESC LIMIT 20",
            ]
        if "data_target" in report_gaps:
            return [
                "SELECT * FROM process_events ORDER BY step DESC LIMIT 20",
                "SELECT * FROM netflow ORDER BY step DESC LIMIT 20",
                "SELECT * FROM alerts ORDER BY step DESC LIMIT 20",
                "SELECT * FROM email_logs ORDER BY step DESC LIMIT 20",
                "SELECT * FROM auth_logs ORDER BY step DESC LIMIT 20",
            ]
        return default

    def query_for_entity(self, entity_value: str, entity_type: str):
        value = quote_sql(entity_value)
        if entity_type == "host":
            return self.action_for_sql(
                "SELECT * FROM auth_logs WHERE host_id = "
                f"{value} ORDER BY step DESC LIMIT 20"
            )
        if entity_type == "user":
            return self.action_for_sql(
                "SELECT * FROM auth_logs WHERE user_id = "
                f"{value} ORDER BY step DESC LIMIT 20"
            )
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
        return self.action_for_sql(self.next_broad_query())
