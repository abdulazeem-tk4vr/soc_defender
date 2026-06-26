from __future__ import annotations

from dataclasses import dataclass, field

from .actions import is_safe_select, query_logs


def quote_sql(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


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



    def query_for_source_table(self, source_table: str):
        candidates = {
            "alerts": "SELECT * FROM alerts ORDER BY step DESC LIMIT 20",
            "auth_logs": "SELECT * FROM auth_logs ORDER BY step DESC LIMIT 20",
            "email_logs": "SELECT * FROM email_logs ORDER BY step DESC LIMIT 20",
            "netflow": "SELECT * FROM netflow ORDER BY step DESC LIMIT 20",
            "process_events": "SELECT * FROM process_events ORDER BY step DESC LIMIT 20",
        }
        sql = candidates.get(source_table)
        if sql is None:
            return self.action_for_sql(self.next_broad_query())
        return self.action_for_sql(sql)

    def query_for_objective_source(self, objective: str | None, source_table: str | None, report_gaps: set[str] | None = None):
        report_gaps = report_gaps or set()
        ordered_sources = {
            "find_identity": ["auth_logs", "email_logs", "alerts"],
            "find_patient_zero": ["auth_logs", "alerts", "process_events"],
            "find_attacker_domain": ["netflow", "alerts", "process_events"],
            "find_data_target": ["process_events", "alerts"],
            "corroborate_containment": ["alerts", "auth_logs", "netflow", "process_events"],
        }.get(objective or "", [])
        sources = []
        if source_table:
            sources.append(source_table)
        sources.extend(source for source in ordered_sources if source not in sources)
        for source in sources:
            sql = {
                "alerts": "SELECT * FROM alerts ORDER BY step DESC LIMIT 20",
                "auth_logs": "SELECT * FROM auth_logs ORDER BY step DESC LIMIT 20",
                "email_logs": "SELECT * FROM email_logs ORDER BY step DESC LIMIT 20",
                "netflow": "SELECT * FROM netflow ORDER BY step DESC LIMIT 20",
                "process_events": "SELECT * FROM process_events ORDER BY step DESC LIMIT 20",
            }.get(source)
            if sql and sql not in self.failed_queries and not self.already_emitted(sql):
                return self.action_for_sql(sql)
        return self.action_for_sql(self.next_broad_query(report_gaps))

    def query_for_objective(self, objective: str, report_gaps: set[str] | None = None):
        report_gaps = report_gaps or set()
        candidates = {
            "find_identity": [
                "SELECT * FROM auth_logs ORDER BY step DESC LIMIT 20",
                "SELECT * FROM email_logs ORDER BY step DESC LIMIT 20",
                "SELECT * FROM alerts ORDER BY step DESC LIMIT 20",
            ],
            "find_patient_zero": [
                "SELECT * FROM auth_logs ORDER BY step DESC LIMIT 20",
                "SELECT * FROM process_events ORDER BY step DESC LIMIT 20",
                "SELECT * FROM alerts ORDER BY step DESC LIMIT 20",
            ],
            "find_attacker_domain": [
                "SELECT * FROM netflow ORDER BY step DESC LIMIT 20",
                "SELECT * FROM alerts ORDER BY step DESC LIMIT 20",
            ],
            "find_data_target": [
                "SELECT * FROM process_events ORDER BY step DESC LIMIT 20",
                "SELECT * FROM alerts ORDER BY step DESC LIMIT 20",
            ],
            "corroborate_containment": [
                "SELECT * FROM alerts ORDER BY step DESC LIMIT 20",
                "SELECT * FROM auth_logs ORDER BY step DESC LIMIT 20",
                "SELECT * FROM netflow ORDER BY step DESC LIMIT 20",
                "SELECT * FROM process_events ORDER BY step DESC LIMIT 20",
            ],
        }.get(objective, [])
        for sql in candidates:
            if sql not in self.failed_queries and not self.already_emitted(sql):
                return self.action_for_sql(sql)
        return self.action_for_sql(self.next_broad_query(report_gaps))

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
        return self.action_for_sql(f"SELECT * FROM alerts WHERE message LIKE {quote_sql('%' + entity_value + '%')} ORDER BY step DESC LIMIT 20")
