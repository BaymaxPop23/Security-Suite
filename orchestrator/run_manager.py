"""Simplified Run Manager - Direct Task Execution"""
from typing import Dict, Any, List
from datetime import datetime
import uuid
import json
from pathlib import Path

from core.schemas import Task, TaskType, TaskStatus, TaskPriority
from core.storage.task_store import TaskStore
from orchestrator.dispatcher import Dispatcher


class RunManager:
    """
    Simplified Run Manager for direct task execution

    Responsibilities:
    - Create tasks from domains/APKs
    - Execute tasks via dispatcher
    - Track run progress
    """

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.task_store = TaskStore()
        self.dispatcher = Dispatcher(dry_run=dry_run)

    def start_run(self, scope: Dict[str, Any]) -> str:
        """
        Start a new security assessment run

        Args:
            scope: {
                'domains': [...],  # Domains to scan
                'apks': [...],     # APK files/URLs to analyze
            }

        Returns:
            Run ID
        """
        run_id = f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

        # Save run metadata
        run_dir = Path(f"runs/{run_id}")
        run_dir.mkdir(parents=True, exist_ok=True)

        run_metadata = {
            "run_id": run_id,
            "started_at": datetime.now().isoformat(),
            "scope": scope,
            "status": "started",
            "tasks": []
        }

        with open(run_dir / "metadata.json", 'w') as f:
            json.dump(run_metadata, f, indent=2)

        # Create tasks directly from scope
        tasks = self._create_tasks_from_scope(scope)

        # Save tasks
        for task in tasks:
            self.task_store.create(task)

        # Update run metadata
        run_metadata['tasks'] = [t.id for t in tasks]
        run_metadata['total_tasks'] = len(tasks)

        with open(run_dir / "metadata.json", 'w') as f:
            json.dump(run_metadata, f, indent=2)

        return run_id

    def _create_tasks_from_scope(self, scope: Dict[str, Any]) -> List[Task]:
        """Create tasks directly from domains and APKs"""
        tasks = []

        # Create recon tasks for domains
        domains = scope.get('domains', [])
        for domain in domains:
            task_id = f"task_recon_{uuid.uuid4().hex[:8]}"
            tasks.append(Task(
                id=task_id,
                title=f"Recon: {domain}",
                type=TaskType.RECON,
                priority=TaskPriority.HIGH,
                assignee_agent="recon",
                inputs={"domain": domain},
                status=TaskStatus.PENDING
            ))

        # Create APK analysis tasks
        apks = scope.get('apks', [])
        for apk in apks:
            task_id = f"task_apk_{uuid.uuid4().hex[:8]}"
            # Determine if it's a path or URL
            if apk.startswith('http://') or apk.startswith('https://'):
                inputs = {"apk_url": apk}
                title = f"APK Analysis: {apk.split('/')[-1]}"
            else:
                inputs = {"apk_path": apk}
                title = f"APK Analysis: {Path(apk).name}"

            tasks.append(Task(
                id=task_id,
                title=title,
                type=TaskType.APK_ANALYSIS,
                priority=TaskPriority.HIGH,
                assignee_agent="apk_analyzer",
                inputs=inputs,
                status=TaskStatus.PENDING
            ))

        return tasks

    def execute_run(self, run_id: str) -> Dict[str, Any]:
        """
        Execute all tasks in a run

        Args:
            run_id: Run identifier

        Returns:
            Run summary
        """
        run_dir = Path(f"runs/{run_id}")

        # Load run metadata
        with open(run_dir / "metadata.json", 'r') as f:
            run_metadata = json.load(f)

        task_ids = run_metadata['tasks']
        completed = 0
        failed = 0

        # Execute all tasks
        for task_id in task_ids:
            task = self.task_store.get(task_id)
            if not task:
                failed += 1
                continue

            result = self.dispatcher.dispatch(task)

            if result['success']:
                completed += 1
            else:
                failed += 1

        # Update run metadata
        run_metadata['completed_at'] = datetime.now().isoformat()
        run_metadata['status'] = 'completed'
        run_metadata['summary'] = {
            'total_tasks': len(task_ids),
            'completed': completed,
            'failed': failed
        }

        with open(run_dir / "metadata.json", 'w') as f:
            json.dump(run_metadata, f, indent=2)

        return run_metadata

    def get_run_status(self, run_id: str) -> Dict[str, Any]:
        """Get current status of a run"""
        run_dir = Path(f"runs/{run_id}")

        if not run_dir.exists():
            return {"error": "Run not found"}

        with open(run_dir / "metadata.json", 'r') as f:
            metadata = json.load(f)

        # Get task statistics
        task_ids = metadata.get('tasks', [])
        tasks = [self.task_store.get(tid) for tid in task_ids]

        status_counts = {
            'pending': 0,
            'in_progress': 0,
            'completed': 0,
            'failed': 0,
            'blocked': 0
        }

        for task in tasks:
            if task:
                status_counts[task.status.value] += 1

        return {
            "run_id": run_id,
            "status": metadata.get('status'),
            "started_at": metadata.get('started_at'),
            "completed_at": metadata.get('completed_at'),
            "total_tasks": len(task_ids),
            "task_status": status_counts,
            "scope": metadata.get('scope')
        }
