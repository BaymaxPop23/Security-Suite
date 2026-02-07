"""Artifact indexing schema"""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field
from enum import Enum


class ArtifactType(str, Enum):
    RECON_REPORT = "recon_report"
    SUBDOMAIN_LIST = "subdomain_list"
    PORT_SCAN = "port_scan"
    TECH_STACK = "tech_stack"
    APK_MANIFEST = "apk_manifest"
    DECOMPILED_CODE = "decompiled_code"
    TEST_PLAN = "test_plan"
    VULNERABILITY_REPORT = "vulnerability_report"
    CODE_REVIEW_REPORT = "code_review_report"
    HTML_REPORT = "html_report"
    RAW_OUTPUT = "raw_output"
    SCREENSHOT = "screenshot"
    PCAP = "pcap"


class ArtifactIndex(BaseModel):
    """Schema for tracking all artifacts produced by agents"""
    artifact_id: str = Field(..., description="Unique artifact identifier")
    type: ArtifactType = Field(..., description="Type of artifact")

    path: str = Field(..., description="Absolute or relative path to artifact")

    produced_by: str = Field(..., description="Agent that produced this")
    related_task_id: Optional[str] = Field(None, description="Task this belongs to")
    related_run_id: Optional[str] = Field(None, description="Run that produced this")

    hash: str = Field(..., description="SHA256 hash of artifact content")
    size_bytes: Optional[int] = Field(None, description="File size in bytes")

    metadata: dict = Field(
        default_factory=dict,
        description="Additional artifact-specific metadata"
    )

    created_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_schema_extra = {
            "example": {
                "artifact_id": "artifact_001",
                "type": "recon_report",
                "path": "/artifacts/recon/run_001/subdomains.json",
                "produced_by": "recon",
                "related_task_id": "task_001",
                "related_run_id": "run_001",
                "hash": "sha256:abc123...",
                "size_bytes": 4096,
                "metadata": {
                    "target": "example.com",
                    "total_subdomains": 42
                }
            }
        }
