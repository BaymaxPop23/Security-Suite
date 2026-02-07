"""Structured JSONL logging for all agents"""
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
from enum import Enum


class LogLevel(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class StructuredLogger:
    """
    JSONL logger for agent activities
    Each log entry is a single-line JSON object
    """

    def __init__(self, log_file: Path, agent_name: str, run_id: str):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.agent_name = agent_name
        self.run_id = run_id

    def _write_log(self, level: LogLevel, message: str, **kwargs):
        """Write a log entry"""
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": level.value,
            "agent": self.agent_name,
            "run_id": self.run_id,
            "message": message,
            **kwargs
        }

        with open(self.log_file, 'a') as f:
            f.write(json.dumps(entry) + '\n')

    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self._write_log(LogLevel.DEBUG, message, **kwargs)

    def info(self, message: str, **kwargs):
        """Log info message"""
        self._write_log(LogLevel.INFO, message, **kwargs)

    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self._write_log(LogLevel.WARNING, message, **kwargs)

    def error(self, message: str, **kwargs):
        """Log error message"""
        self._write_log(LogLevel.ERROR, message, **kwargs)

    def critical(self, message: str, **kwargs):
        """Log critical message"""
        self._write_log(LogLevel.CRITICAL, message, **kwargs)

    def log_task_start(self, task_id: str, task_type: str):
        """Log task execution start"""
        self.info(
            f"Starting task: {task_type}",
            event="task_start",
            task_id=task_id,
            task_type=task_type
        )

    def log_task_complete(self, task_id: str, duration_seconds: float, outputs: Dict[str, Any]):
        """Log task completion"""
        self.info(
            f"Task completed in {duration_seconds:.2f}s",
            event="task_complete",
            task_id=task_id,
            duration_seconds=duration_seconds,
            outputs=outputs
        )

    def log_tool_execution(self, tool_name: str, command: str, exit_code: int, duration: float):
        """Log tool execution"""
        self.info(
            f"Tool executed: {tool_name}",
            event="tool_execution",
            tool_name=tool_name,
            command=command,
            exit_code=exit_code,
            duration_seconds=duration
        )

    def log_llm_call(self, model: str, prompt_length: int, response_length: int, duration: float):
        """Log LLM API call"""
        self.info(
            f"LLM call: {model}",
            event="llm_call",
            model=model,
            prompt_length=prompt_length,
            response_length=response_length,
            duration_seconds=duration
        )

    def log_finding(self, finding_id: str, severity: str, title: str):
        """Log finding discovery"""
        self.info(
            f"Finding discovered: {title}",
            event="finding_discovered",
            finding_id=finding_id,
            severity=severity,
            title=title
        )

    def log_artifact(self, artifact_id: str, artifact_type: str, path: str):
        """Log artifact creation"""
        self.info(
            f"Artifact created: {artifact_type}",
            event="artifact_created",
            artifact_id=artifact_id,
            artifact_type=artifact_type,
            path=path
        )

    def read_logs(self, filter_level: Optional[LogLevel] = None) -> list:
        """Read all log entries with optional filtering"""
        if not self.log_file.exists():
            return []

        entries = []
        with open(self.log_file, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())
                    if filter_level is None or entry.get('level') == filter_level.value:
                        entries.append(entry)
                except json.JSONDecodeError:
                    continue

        return entries
