"""Findings endpoints"""
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional, Any, Dict
from datetime import datetime

from core.schemas import Finding, CodeFinding, Severity, FindingStatus, CodeSeverity, CodeFindingStatus
from core.storage.finding_store import FindingStore, CodeFindingStore

router = APIRouter()


class FindingResponse(BaseModel):
    """Finding response"""
    id: str
    title: str
    severity: str
    confidence: str
    description: str
    evidence_safe: Dict[str, Any]
    affected_assets: List[str]
    remediation: str
    status: str
    created_at: datetime


class CodeFindingResponse(BaseModel):
    """Code finding response"""
    id: str
    title: str
    severity: str
    confidence: str
    file_path: str
    line_ranges: List[List[int]]
    snippet_safe: str
    reasoning: str
    remediation: str
    status: str
    created_at: datetime


@router.get("/findings")
async def list_findings(
    severity: Optional[Severity] = Query(None),
    status: Optional[FindingStatus] = Query(None),
    limit: int = Query(100, le=1000)
) -> List[FindingResponse]:
    """List findings with optional filters"""
    try:
        finding_store = FindingStore()
        findings = finding_store.list(severity=severity, status=status, limit=limit)

        return [
            FindingResponse(
                id=f.id,
                title=f.title,
                severity=f.severity.value,
                confidence=f.confidence.value,
                description=f.description,
                evidence_safe=f.evidence_safe,
                affected_assets=f.affected_assets,
                remediation=f.remediation,
                status=f.status.value,
                created_at=f.created_at
            )
            for f in findings
        ]

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/findings/code")
async def list_code_findings(
    severity: Optional[CodeSeverity] = Query(None),
    status: Optional[CodeFindingStatus] = Query(None),
    limit: int = Query(100, le=1000)
) -> List[CodeFindingResponse]:
    """List code findings with optional filters"""
    try:
        code_finding_store = CodeFindingStore()
        findings = code_finding_store.list(severity=severity, status=status, limit=limit)

        return [
            CodeFindingResponse(
                id=cf.id,
                title=cf.title,
                severity=cf.severity.value,
                confidence=cf.confidence.value,
                file_path=cf.file_path,
                line_ranges=cf.line_ranges,
                snippet_safe=cf.snippet_safe,
                reasoning=cf.reasoning,
                remediation=cf.remediation,
                status=cf.status.value,
                created_at=cf.created_at
            )
            for cf in findings
        ]

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/findings/{finding_id}")
async def get_finding(finding_id: str) -> Finding:
    """Get a specific finding"""
    try:
        finding_store = FindingStore()
        finding = finding_store.get(finding_id)

        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        return finding

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
