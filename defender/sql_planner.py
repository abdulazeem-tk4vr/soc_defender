from __future__ import annotations

from dataclasses import dataclass, field

from .actions import is_safe_select, query_logs


def quote_sql(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


@dataclass
class SQLPlanner:
    failed_queries: set[str] = field(default_factory=set)
    emitted_queries: set[str] = field(default_factory=set)
    last_emitted_sql: str | None = None

    def record_failure(self, sql: str) -> None:
        self.failed_queries.add(sql.strip())

    def already_emitted(self, sql: str) -> bool:
        return sql.strip() in self.emitted_queries

    def action_for_sql(self, sql: str):
        sql = self.repair(sql)
        self.emitted_queries.add(sql)
        self.last_emitted_sql = sql
        return query_logs(sql)

    def repair(self, sql: str) -> str:
        sql = sql.strip()
        if is_safe_select(sql) and sql not in self.failed_queries and not self.already_emitted(sql):
            return sql
        return self.next_broad_query()

    def next_broad_query(self):
        candidates = [
            "SELECT * FROM alerts ORDER BY step DESC LIMIT 20",
            "SELECT * FROM email_logs ORDER BY step DESC LIMIT 20",
            "SELECT * FROM auth_logs ORDER BY step DESC LIMIT 20",
            "SELECT * FROM netflow ORDER BY step DESC LIMIT 20",
            "SELECT * FROM process_events ORDER BY step DESC LIMIT 20",
        ]
        for sql in candidates:
            if sql not in self.failed_queries and not self.already_emitted(sql):
                return sql
        # The benchmark still needs one legal action per step. If all broad
        # probes are exhausted, repeat the least risky valid evidence query.
        return "SELECT * FROM alerts ORDER BY step DESC LIMIT 20"

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
