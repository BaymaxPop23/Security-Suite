"""Task data model schema"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class TaskType(str, Enum):
    RECON = "recon"
    PLANNING = "planning"
    SECURITY_TESTING = "security_testing"
    CODE_REVIEW = "code_review"
    APK_ANALYSIS = "apk_analysis"
    REPORTING = "reporting"


class TaskStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    FAILED = "failed"


class TaskPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Task(BaseModel):
    """Task schema for orchestration and tracking"""
    id: str = Field(..., description="Unique task identifier")
    title: str = Field(..., description="Human-readable task title")
    type: TaskType = Field(..., description="Type of task")
    priority: TaskPriority = Field(default=TaskPriority.MEDIUM)
    status: TaskStatus = Field(default=TaskStatus.PENDING)
    assignee_agent: Optional[str] = Field(None, description="Agent assigned to this task")

    inputs: Dict[str, Any] = Field(default_factory=dict, description="Input parameters for task")
    outputs: Dict[str, Any] = Field(default_factory=dict, description="Task outputs (artifact IDs, finding IDs)")

    blocked_by: List[str] = Field(default_factory=list, description="Task IDs that block this task")
    blocks: List[str] = Field(default_factory=list, description="Task IDs blocked by this task")

    error_message: Optional[str] = Field(None, description="Error message if task failed")

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    class Config:
        json_schema_extra = {
            "example": {
                "id": "task_001",
                "title": "Analyze APK for hardcoded secrets",
                "type": "apk_analysis",
                "priority": "high",
                "status": "in_progress",
                "assignee_agent": "apk-analyzer",
                "inputs": {
                    "apk_path": "/path/to/app.apk",
                    "scope": ["com.example.app"]
                },
                "outputs": {
                    "artifact_ids": ["artifact_123"],
                    "finding_ids": ["finding_456"]
                },
                "blocked_by": [],
                "blocks": ["task_002"]
            }
        }
