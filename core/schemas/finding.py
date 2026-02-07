"""Finding data model schema for security vulnerabilities"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingStatus(str, Enum):
    OPEN = "open"
    IN_REVIEW = "in_review"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    MITIGATED = "mitigated"
    ACCEPTED_RISK = "accepted_risk"


class Finding(BaseModel):
    """Security finding/vulnerability schema"""
    id: str = Field(..., description="Unique finding identifier")
    title: str = Field(..., description="Short vulnerability title")
    severity: Severity = Field(..., description="Severity level")
    confidence: Confidence = Field(..., description="Confidence in finding")

    description: str = Field(..., description="Detailed description of vulnerability")

    evidence_safe: Dict[str, Any] = Field(
        default_factory=dict,
        description="Evidence with sensitive data redacted"
    )

    affected_assets: List[str] = Field(
        default_factory=list,
        description="List of affected targets/endpoints/assets"
    )

    remediation: str = Field(..., description="Remediation guidance")
    references: List[str] = Field(
        default_factory=list,
        description="External references (OWASP, CVE, etc.)"
    )

    status: FindingStatus = Field(default=FindingStatus.OPEN)

    discovered_by: Optional[str] = Field(None, description="Agent that discovered this")
    task_id: Optional[str] = Field(None, description="Task that produced this finding")
    run_id: Optional[str] = Field(None, description="Run ID where this was found")

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_schema_extra = {
            "example": {
                "id": "finding_001",
                "title": "SQL Injection in login endpoint",
                "severity": "critical",
                "confidence": "high",
                "description": "The login endpoint is vulnerable to SQL injection...",
                "evidence_safe": {
                    "request": "POST /api/login HTTP/1.1...",
                    "response": "SQL error: syntax near 'admin'--'",
                    "poc_safe": "username=admin' OR '1'='1"
                },
                "affected_assets": ["api.example.com/login"],
                "remediation": "Use parameterized queries instead of string concatenation",
                "references": ["OWASP A03:2021"],
                "status": "open"
            }
        }
