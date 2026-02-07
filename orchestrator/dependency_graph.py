"""Task dependency graph management"""
from typing import List, Set, Dict
from core.schemas import Task, TaskStatus
from core.storage.task_store import TaskStore


class DependencyGraph:
    """
    Manages task dependencies and determines execution order
    """

    def __init__(self):
        self.task_store = TaskStore()

    def get_ready_tasks(self) -> List[Task]:
        """
        Get all tasks that are ready to execute
        (pending status with no blocking dependencies)

        Returns:
            List of tasks ready for execution
        """
        # Get all pending tasks
        pending_tasks = self.task_store.list(status=TaskStatus.PENDING)

        ready_tasks = []
        for task in pending_tasks:
            if self._is_ready(task):
                ready_tasks.append(task)

        return ready_tasks

    def get_blocked_tasks(self) -> List[Task]:
        """Get all tasks that are currently blocked"""
        return self.task_store.get_blocked_tasks()

    def mark_blocked(self, task_id: str, blocked_by: List[str]):
        """Mark a task as blocked by other tasks"""
        self.task_store.update(
            task_id,
            status=TaskStatus.BLOCKED,
            blocked_by=blocked_by
        )

    def unblock_dependents(self, completed_task_id: str):
        """
        Unblock tasks that were waiting for the completed task

        Args:
            completed_task_id: ID of task that just completed
        """
        # Get all blocked tasks
        blocked_tasks = self.get_blocked_tasks()

        for task in blocked_tasks:
            if completed_task_id in task.blocked_by:
                # Remove this dependency
                updated_blocked_by = [
                    dep for dep in task.blocked_by
                    if dep != completed_task_id
                ]

                # If no more blockers, mark as pending
                if not updated_blocked_by:
                    self.task_store.update(
                        task.id,
                        status=TaskStatus.PENDING,
                        blocked_by=[]
                    )
                else:
                    self.task_store.update(
                        task.id,
                        blocked_by=updated_blocked_by
                    )

    def validate_dependencies(self, tasks: List[Task]) -> bool:
        """
        Validate that task dependencies form a valid DAG (no cycles)

        Args:
            tasks: List of tasks to validate

        Returns:
            True if valid, False if cycle detected
        """
        task_map = {t.id: t for t in tasks}

        # DFS cycle detection
        visited = set()
        rec_stack = set()

        def has_cycle(task_id: str) -> bool:
            visited.add(task_id)
            rec_stack.add(task_id)

            task = task_map.get(task_id)
            if task:
                for dep_id in task.blocked_by:
                    if dep_id not in visited:
                        if has_cycle(dep_id):
                            return True
                    elif dep_id in rec_stack:
                        return True

            rec_stack.remove(task_id)
            return False

        for task in tasks:
            if task.id not in visited:
                if has_cycle(task.id):
                    return False

        return True

    def _is_ready(self, task: Task) -> bool:
        """Check if a task is ready to execute"""
        if task.status != TaskStatus.PENDING:
            return False

        # Check if all blocking tasks are completed
        if not task.blocked_by:
            return True

        for dep_id in task.blocked_by:
            dep_task = self.task_store.get(dep_id)
            if not dep_task or dep_task.status != TaskStatus.COMPLETED:
                return False

        return True

    def topological_sort(self, tasks: List[Task]) -> List[Task]:
        """
        Sort tasks in topological order (dependencies first)

        Args:
            tasks: List of tasks to sort

        Returns:
            Sorted list of tasks
        """
        task_map = {t.id: t for t in tasks}
        visited = set()
        result = []

        def visit(task_id: str):
            if task_id in visited:
                return
            visited.add(task_id)

            task = task_map.get(task_id)
            if task:
                # Visit dependencies first
                for dep_id in task.blocked_by:
                    if dep_id in task_map:
                        visit(dep_id)

                result.append(task)

        for task in tasks:
            visit(task.id)

        return result
