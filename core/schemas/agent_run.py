"""Agent run tracking schema"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class RunStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentRun(BaseModel):
    """Schema for tracking individual agent execution runs"""
    id: str = Field(..., description="Unique run identifier")
    agent_name: str = Field(..., description="Name of agent that ran")
    task_id: Optional[str] = Field(None, description="Task this run belongs to")

    start_time: datetime = Field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None

    status: RunStatus = Field(default=RunStatus.QUEUED)

    logs_jsonl_path: str = Field(..., description="Path to JSONL log file")

    produced_artifacts: List[str] = Field(
        default_factory=list,
        description="List of artifact IDs produced"
    )

    produced_findings: List[str] = Field(
        default_factory=list,
        description="List of finding IDs produced"
    )

    produced_code_findings: List[str] = Field(
        default_factory=list,
        description="List of code finding IDs produced"
    )

    metrics: Dict[str, Any] = Field(
        default_factory=dict,
        description="Performance and output metrics"
    )

    error_message: Optional[str] = Field(None, description="Error if run failed")

    dry_run: bool = Field(default=False, description="Whether this was a dry run")

    class Config:
        json_schema_extra = {
            "example": {
                "id": "run_001",
                "agent_name": "recon",
                "task_id": "task_001",
                "start_time": "2026-02-07T12:00:00Z",
                "end_time": "2026-02-07T12:15:00Z",
                "status": "completed",
                "logs_jsonl_path": "/logs/recon/run_001.jsonl",
                "produced_artifacts": ["artifact_001", "artifact_002"],
                "produced_findings": [],
                "produced_code_findings": [],
                "metrics": {
                    "subdomains_found": 42,
                    "ports_scanned": 1000,
                    "duration_seconds": 900
                }
            }
        }
