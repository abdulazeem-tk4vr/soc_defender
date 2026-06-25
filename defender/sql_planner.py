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

GAP_QUERY_TEMPLATES = {
    "attacker_domain": (
        "SELECT * FROM netflow WHERE dst_domain IS NOT NULL ORDER BY step DESC LIMIT 20",
        "SELECT * FROM alerts WHERE message LIKE '%dst_domain=%' ORDER BY step DESC LIMIT 20",
        "SELECT * FROM alerts WHERE message LIKE '%domain=%' ORDER BY step DESC LIMIT 20",
    ),
    "data_target": (
        "SELECT * FROM process_events WHERE command_line LIKE '%exfil%' ORDER BY step DESC LIMIT 20",
        "SELECT * FROM alerts WHERE message LIKE '%target=%' ORDER BY step DESC LIMIT 20",
        "SELECT * FROM netflow WHERE bytes_sent IS NOT NULL ORDER BY step DESC LIMIT 20",
    ),
}

ENTITY_QUERY_PATTERNS = (
    re.compile(r"^SELECT \* FROM auth_logs WHERE host_id = '[^']*(?:''[^']*)*' ORDER BY step DESC LIMIT 20$"),
    re.compile(r"^SELECT \* FROM auth_logs WHERE user_id = '[^']*(?:''[^']*)*' ORDER BY step DESC LIMIT 20$"),
    re.compile(r"^SELECT \* FROM netflow WHERE dst_domain = '[^']*(?:''[^']*)*' ORDER BY step DESC LIMIT 20$"),
    re.compile(r"^SELECT \* FROM process_events WHERE command_line LIKE '[^']*(?:''[^']*)*' ORDER BY step DESC LIMIT 20$"),
)

GAP_QUERY_PATTERNS = (
    re.compile(r"^SELECT \* FROM netflow WHERE dst_domain IS NOT NULL ORDER BY step DESC LIMIT 20$"),
    re.compile(r"^SELECT \* FROM alerts WHERE message LIKE '%dst_domain=%' ORDER BY step DESC LIMIT 20$"),
    re.compile(r"^SELECT \* FROM alerts WHERE message LIKE '%domain=%' ORDER BY step DESC LIMIT 20$"),
    re.compile(r"^SELECT \* FROM process_events WHERE command_line LIKE '%exfil%' ORDER BY step DESC LIMIT 20$"),
    re.compile(r"^SELECT \* FROM alerts WHERE message LIKE '%target=%' ORDER BY step DESC LIMIT 20$"),
    re.compile(r"^SELECT \* FROM netflow WHERE bytes_sent IS NOT NULL ORDER BY step DESC LIMIT 20$"),
)


def is_allowlisted_template(sql: str) -> bool:
    sql = sql.strip()
    return (
        sql in BROAD_QUERY_TEMPLATES
        or any(pattern.match(sql) for pattern in ENTITY_QUERY_PATTERNS)
        or any(pattern.match(sql) for pattern in GAP_QUERY_PATTERNS)
    )


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

    def action_for_sql(self, sql: str, report_gaps: set[str] | None = None):
        sql = self.repair(sql, report_gaps=report_gaps)
        self.emitted_queries.add(sql)
        self.emitted_counts[sql] = self.emitted_counts.get(sql, 0) + 1
        self.last_emitted_sql = sql
        return query_logs(sql)

    def repair(self, sql: str, report_gaps: set[str] | None = None) -> str:
        sql = self.normalize_sql(sql)
        if is_safe_select(sql) and sql not in self.failed_queries and not self.already_emitted(sql):
            return sql
        return self.next_repair_query(report_gaps)

    @staticmethod
    def normalize_sql(sql: str) -> str:
        sql = sql.strip()
        if sql.endswith(";"):
            return sql[:-1].strip()
        return sql

    def next_repair_query(self, report_gaps: set[str] | None = None) -> str:
        report_gaps = report_gaps or set()
        for report_field in ("attacker_domain", "data_target"):
            if report_field in report_gaps:
                return self.next_gap_query(report_field)
        return self.next_broad_query(report_gaps)

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

    def next_gap_query(self, report_field: str) -> str:
        candidates = list(GAP_QUERY_TEMPLATES.get(report_field, ()))
        for sql in candidates:
            if sql not in self.failed_queries and not self.already_emitted(sql):
                return sql
        available = [sql for sql in candidates if sql not in self.failed_queries]
        if available:
            return min(available, key=lambda sql: self.emitted_counts.get(sql, 0))
        return self.next_broad_query({report_field})

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
            value = quote_sql(f"%{entity_value}%")
            return self.action_for_sql(
                "SELECT * FROM process_events WHERE command_line LIKE "
                f"{value} ORDER BY step DESC LIMIT 20"
            )
        return self.action_for_sql(self.next_broad_query())
