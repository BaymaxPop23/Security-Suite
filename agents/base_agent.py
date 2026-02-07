"""Base agent class with standard interface"""
from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime
import json

from core.schemas import Task, Finding, CodeFinding
from core.llm import get_llm_router, TaskComplexity
from core.logging import StructuredLogger, ArtifactTracker
from core.tools import ToolRunner


class RunResult:
    """Standard result from agent run"""
    def __init__(
        self,
        success: bool,
        artifacts: List[str] = None,
        findings: List[str] = None,
        code_findings: List[str] = None,
        error: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        self.success = success
        self.artifacts = artifacts or []
        self.findings = findings or []
        self.code_findings = code_findings or []
        self.error = error
        self.metadata = metadata or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "artifacts": self.artifacts,
            "findings": self.findings,
            "code_findings": self.code_findings,
            "error": self.error,
            "metadata": self.metadata
        }


class BaseAgent(ABC):
    """
    Abstract base class for all agents
    Implements standard interface: plan(), run(), report()
    """

    def __init__(
        self,
        name: str,
        model: Optional[str] = None,
        dry_run: bool = False,
        prefer_claude: bool = True,  # Use Claude by default for better quality!
        require_llm: bool = True
    ):
        self.name = name
        self.model = model
        self.dry_run = dry_run
        self.prefer_claude = prefer_claude
        self.require_llm = require_llm
        self.llm = get_llm_router(prefer_claude=prefer_claude)
        self.tool_runner = ToolRunner(dry_run=dry_run)

    def _setup_run(self, run_id: str, task_id: str = None) -> tuple:
        """Setup logging and artifact tracking for a run"""
        # Create agent_run record in database (required for foreign key constraints)
        from core.storage.database import get_db
        from datetime import datetime

        db = get_db()
        db.execute(
            """INSERT INTO agent_runs (
                id, agent_name, task_id, start_time, status, logs_jsonl_path, dry_run
            ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (run_id, self.name, task_id, datetime.now(), 'running', f"logs/{self.name}/{run_id}.jsonl", 1 if self.dry_run else 0)
        )

        # Create log directory
        log_dir = Path(f"logs/{self.name}")
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"{run_id}.jsonl"

        # Create artifact directory
        artifact_dir = Path(f"artifacts/{self.name}/{run_id}")
        artifact_dir.mkdir(parents=True, exist_ok=True)

        # Initialize logger and tracker
        logger = StructuredLogger(log_file, self.name, run_id)
        tracker = ArtifactTracker(self.name, run_id)

        return logger, tracker, artifact_dir

    @abstractmethod
    def plan(self, context: Dict[str, Any]) -> List[Task]:
        """
        Generate tasks based on context

        Args:
            context: Dict with scope, previous results, etc.

        Returns:
            List of Task objects
        """
        pass

    @abstractmethod
    def run(self, task: Task, run_id: str) -> RunResult:
        """
        Execute a task and return results

        Args:
            task: Task object to execute
            run_id: Unique run identifier

        Returns:
            RunResult with artifacts and findings
        """
        pass

    @abstractmethod
    def report(self, run_id: str) -> Dict[str, Any]:
        """
        Generate summary report for a run

        Args:
            run_id: Run identifier

        Returns:
            Dict with run summary
        """
        pass

    def _load_prompt(self, prompt_name: str, **kwargs) -> str:
        """Load and format a prompt template"""
        prompt_file = Path(f"agents/{self.name}/prompts/{prompt_name}.txt")

        if not prompt_file.exists():
            return ""

        with open(prompt_file, 'r') as f:
            template = f.read()

        return template.format(**kwargs)

    def _call_llm(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.1,
        json_output: bool = False,
        task_type: Optional[Any] = None,
        complexity: Optional[TaskComplexity] = None
    ) -> Any:
        """
        Call LLM with prompt using intelligent routing

        Args:
            prompt: User prompt
            system: System prompt
            temperature: Sampling temperature
            json_output: Whether to expect JSON response
            task_type: Task type for complexity determination
            complexity: Override complexity level

        Returns:
            LLM response (str or dict if json_output=True)
        """
        if json_output:
            return self.llm.generate_json(
                prompt=prompt,
                system=system,
                temperature=temperature,
                task_type=task_type,
                complexity=complexity
            )
        else:
            result = self.llm.generate(
                prompt=prompt,
                system=system,
                temperature=temperature,
                task_type=task_type,
                complexity=complexity
            )
            return result["response"]

    def _save_json_artifact(
        self,
        data: Any,
        filename: str,
        artifact_dir: Path
    ) -> Path:
        """Save JSON data as artifact"""
        file_path = artifact_dir / filename
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        return file_path

    def _save_text_artifact(
        self,
        text: str,
        filename: str,
        artifact_dir: Path
    ) -> Path:
        """Save text data as artifact"""
        file_path = artifact_dir / filename
        with open(file_path, 'w') as f:
            f.write(text)
        return file_path
