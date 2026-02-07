"""Code finding data model for code security issues"""
from datetime import datetime
from typing import Optional, List, Tuple
from pydantic import BaseModel, Field
from enum import Enum


class CodeSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CodeConfidence(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CodeFindingStatus(str, Enum):
    OPEN = "open"
    IN_REVIEW = "in_review"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"
    WONT_FIX = "wont_fix"


class CodeFinding(BaseModel):
    """Code-level security finding schema"""
    id: str = Field(..., description="Unique code finding identifier")
    title: str = Field(..., description="Short issue title")
    severity: CodeSeverity = Field(..., description="Severity level")
    confidence: CodeConfidence = Field(..., description="Confidence in finding")

    file_path: str = Field(..., description="Relative path to file")
    line_ranges: List[Tuple[int, int]] = Field(
        ...,
        description="List of (start_line, end_line) tuples"
    )

    snippet_safe: str = Field(
        ...,
        description="Code snippet with secrets redacted"
    )

    reasoning: str = Field(
        ...,
        description="Why this is a security issue"
    )

    remediation: str = Field(..., description="How to fix the issue")

    cwe_id: Optional[str] = Field(None, description="CWE identifier if applicable")
    owasp_category: Optional[str] = Field(None, description="OWASP category")

    status: CodeFindingStatus = Field(default=CodeFindingStatus.OPEN)

    discovered_by: Optional[str] = Field(None, description="Agent that found this")
    task_id: Optional[str] = Field(None, description="Task that produced this")
    run_id: Optional[str] = Field(None, description="Run ID where this was found")

    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        json_schema_extra = {
            "example": {
                "id": "code_finding_001",
                "title": "Hardcoded API key in configuration",
                "severity": "high",
                "confidence": "confirmed",
                "file_path": "src/config/api.java",
                "line_ranges": [[42, 45]],
                "snippet_safe": "private static final String API_KEY = \"REDACTED_32_CHARS\";",
                "reasoning": "Hardcoded credentials should never be in source code",
                "remediation": "Use environment variables or secret management service",
                "cwe_id": "CWE-798",
                "owasp_category": "A07:2021 - Identification and Authentication Failures",
                "status": "open"
            }
        }
