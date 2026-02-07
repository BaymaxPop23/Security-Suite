"""SQLite database connection and migrations"""
import sqlite3
from pathlib import Path
from typing import Optional
import json
from datetime import datetime


class Database:
    """SQLite database manager with connection pooling"""

    def __init__(self, db_path: str = "security_suite.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None

    def connect(self) -> sqlite3.Connection:
        """Get or create database connection"""
        if self._conn is None:
            self._conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                detect_types=sqlite3.PARSE_DECLTYPES
            )
            self._conn.row_factory = sqlite3.Row
            # Enable foreign keys
            self._conn.execute("PRAGMA foreign_keys = ON")
        return self._conn

    def close(self):
        """Close database connection"""
        if self._conn:
            self._conn.close()
            self._conn = None

    def initialize(self):
        """Initialize database schema"""
        conn = self.connect()
        cursor = conn.cursor()

        # Tasks table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                type TEXT NOT NULL,
                priority TEXT NOT NULL DEFAULT 'medium',
                status TEXT NOT NULL DEFAULT 'pending',
                assignee_agent TEXT,
                inputs TEXT,  -- JSON
                outputs TEXT,  -- JSON
                blocked_by TEXT,  -- JSON array
                blocks TEXT,  -- JSON array
                error_message TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                started_at TIMESTAMP,
                completed_at TIMESTAMP
            )
        """)

        # Findings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                description TEXT NOT NULL,
                evidence_safe TEXT,  -- JSON
                affected_assets TEXT,  -- JSON array
                remediation TEXT NOT NULL,
                refs TEXT,  -- JSON array (renamed from references)
                status TEXT NOT NULL DEFAULT 'open',
                discovered_by TEXT,
                task_id TEXT,
                run_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (task_id) REFERENCES tasks(id)
            )
        """)

        # Code findings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS code_findings (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                file_path TEXT NOT NULL,
                line_ranges TEXT NOT NULL,  -- JSON
                snippet_safe TEXT NOT NULL,
                reasoning TEXT NOT NULL,
                remediation TEXT NOT NULL,
                cwe_id TEXT,
                owasp_category TEXT,
                status TEXT NOT NULL DEFAULT 'open',
                discovered_by TEXT,
                task_id TEXT,
                run_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (task_id) REFERENCES tasks(id)
            )
        """)

        # Agent runs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS agent_runs (
                id TEXT PRIMARY KEY,
                agent_name TEXT NOT NULL,
                task_id TEXT,
                start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                end_time TIMESTAMP,
                status TEXT NOT NULL DEFAULT 'queued',
                logs_jsonl_path TEXT NOT NULL,
                produced_artifacts TEXT,  -- JSON array
                produced_findings TEXT,  -- JSON array
                produced_code_findings TEXT,  -- JSON array
                metrics TEXT,  -- JSON
                error_message TEXT,
                dry_run INTEGER DEFAULT 0,
                FOREIGN KEY (task_id) REFERENCES tasks(id)
            )
        """)

        # Artifacts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS artifacts (
                artifact_id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                path TEXT NOT NULL,
                produced_by TEXT NOT NULL,
                related_task_id TEXT,
                related_run_id TEXT,
                hash TEXT NOT NULL,
                size_bytes INTEGER,
                metadata TEXT,  -- JSON
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (related_task_id) REFERENCES tasks(id),
                FOREIGN KEY (related_run_id) REFERENCES agent_runs(id)
            )
        """)

        # Scope configuration table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scope (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scope_name TEXT NOT NULL,
                in_scope TEXT NOT NULL,  -- JSON array
                out_of_scope TEXT,  -- JSON array
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                active INTEGER DEFAULT 1
            )
        """)

        # Create indexes for common queries
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tasks_priority ON tasks(priority)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_code_findings_severity ON code_findings(severity)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_agent_runs_status ON agent_runs(status)")

        conn.commit()

    def execute(self, query: str, params: tuple = ()):
        """Execute a query with parameters"""
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        return cursor

    def fetchone(self, query: str, params: tuple = ()):
        """Fetch one result"""
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchone()

    def fetchall(self, query: str, params: tuple = ()):
        """Fetch all results"""
        conn = self.connect()
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()


# Global database instance
_db = None

def get_db() -> Database:
    """Get global database instance"""
    global _db
    if _db is None:
        _db = Database()
        _db.initialize()
    return _db
