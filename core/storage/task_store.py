"""Task storage operations"""
import json
from typing import List, Optional
from datetime import datetime

from ..schemas.task import Task, TaskStatus
from .database import get_db


class TaskStore:
    """CRUD operations for tasks"""

    def __init__(self):
        self.db = get_db()

    def create(self, task: Task) -> Task:
        """Create a new task"""
        self.db.execute(
            """
            INSERT INTO tasks (
                id, title, type, priority, status, assignee_agent,
                inputs, outputs, blocked_by, blocks, error_message,
                created_at, updated_at, started_at, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                task.id,
                task.title,
                task.type.value,
                task.priority.value,
                task.status.value,
                task.assignee_agent,
                json.dumps(task.inputs),
                json.dumps(task.outputs),
                json.dumps(task.blocked_by),
                json.dumps(task.blocks),
                task.error_message,
                task.created_at,
                task.updated_at,
                task.started_at,
                task.completed_at
            )
        )
        return task

    def get(self, task_id: str) -> Optional[Task]:
        """Get task by ID"""
        row = self.db.fetchone("SELECT * FROM tasks WHERE id = ?", (task_id,))
        if not row:
            return None
        return self._row_to_task(row)

    def list(
        self,
        status: Optional[TaskStatus] = None,
        assignee: Optional[str] = None,
        limit: int = 100
    ) -> List[Task]:
        """List tasks with optional filters"""
        query = "SELECT * FROM tasks WHERE 1=1"
        params = []

        if status:
            query += " AND status = ?"
            params.append(status.value)

        if assignee:
            query += " AND assignee_agent = ?"
            params.append(assignee)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = self.db.fetchall(query, tuple(params))
        return [self._row_to_task(row) for row in rows]

    def update(self, task_id: str, **kwargs) -> Optional[Task]:
        """Update task fields"""
        # Always update updated_at
        kwargs['updated_at'] = datetime.utcnow()

        # Build update query
        set_clauses = []
        params = []

        for key, value in kwargs.items():
            if key in ['inputs', 'outputs', 'blocked_by', 'blocks']:
                value = json.dumps(value)
            elif hasattr(value, 'value'):  # Enum
                value = value.value
            set_clauses.append(f"{key} = ?")
            params.append(value)

        params.append(task_id)

        query = f"UPDATE tasks SET {', '.join(set_clauses)} WHERE id = ?"
        self.db.execute(query, tuple(params))

        return self.get(task_id)

    def delete(self, task_id: str) -> bool:
        """Delete a task"""
        self.db.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
        return True

    def get_blocked_tasks(self) -> List[Task]:
        """Get all tasks that are currently blocked"""
        rows = self.db.fetchall(
            "SELECT * FROM tasks WHERE status = ? AND blocked_by != '[]'",
            (TaskStatus.BLOCKED.value,)
        )
        return [self._row_to_task(row) for row in rows]

    def _row_to_task(self, row) -> Task:
        """Convert database row to Task object"""
        return Task(
            id=row['id'],
            title=row['title'],
            type=row['type'],
            priority=row['priority'],
            status=row['status'],
            assignee_agent=row['assignee_agent'],
            inputs=json.loads(row['inputs']) if row['inputs'] else {},
            outputs=json.loads(row['outputs']) if row['outputs'] else {},
            blocked_by=json.loads(row['blocked_by']) if row['blocked_by'] else [],
            blocks=json.loads(row['blocks']) if row['blocks'] else [],
            error_message=row['error_message'],
            created_at=row['created_at'],
            updated_at=row['updated_at'],
            started_at=row['started_at'],
            completed_at=row['completed_at']
        )
