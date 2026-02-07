"""Simplified Task Dispatcher - Routes to Recon or APK Analyzer"""
from typing import Dict, Any
import uuid

from core.schemas import Task, TaskStatus, TaskType
from core.storage.task_store import TaskStore
from agents.recon import ReconAgent
from agents.apk_analyzer import APKAnalyzerAgent


class Dispatcher:
    """
    Simplified task dispatcher - routes to recon or apk_analyzer agents only
    """

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self.task_store = TaskStore()

        # Initialize agents
        self.agents = {
            "recon": ReconAgent(dry_run=dry_run),
            "apk_analyzer": APKAnalyzerAgent(dry_run=dry_run)
        }

    def dispatch(self, task: Task) -> Dict[str, Any]:
        """
        Dispatch a task to the appropriate agent

        Args:
            task: Task to dispatch

        Returns:
            Dict with execution result
        """
        # Get agent for this task
        agent_name = task.assignee_agent or self._get_default_agent(task.type)

        if agent_name not in self.agents:
            return {
                "success": False,
                "error": f"Unknown agent: {agent_name}. Only 'recon' and 'apk_analyzer' are supported."
            }

        agent = self.agents[agent_name]

        # Update task status to in_progress
        self.task_store.update(
            task.id,
            status=TaskStatus.IN_PROGRESS,
            assignee_agent=agent_name
        )

        # Generate run ID
        run_id = f"run_{uuid.uuid4().hex[:12]}"

        try:
            # Execute task
            result = agent.run(task, run_id)

            # Update task status based on result
            if result.success:
                self.task_store.update(
                    task.id,
                    status=TaskStatus.COMPLETED,
                    outputs=result.metadata
                )
            else:
                self.task_store.update(
                    task.id,
                    status=TaskStatus.FAILED,
                    error_message=result.error
                )

            return {
                "success": result.success,
                "result": result.metadata if result.success else None,
                "error": result.error if not result.success else None
            }

        except Exception as e:
            # Mark task as failed
            self.task_store.update(
                task.id,
                status=TaskStatus.FAILED,
                error_message=str(e)
            )

            return {
                "success": False,
                "error": str(e)
            }

    def _get_default_agent(self, task_type: TaskType) -> str:
        """Map task type to default agent"""
        mapping = {
            TaskType.RECON: "recon",
            TaskType.APK_ANALYSIS: "apk_analyzer"
        }
        return mapping.get(task_type, "recon")
