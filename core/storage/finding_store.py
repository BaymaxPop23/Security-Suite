"""Finding storage operations"""
import json
from typing import List, Optional

from ..schemas.finding import Finding, Severity, FindingStatus
from ..schemas.code_finding import CodeFinding, CodeSeverity, CodeFindingStatus
from .database import get_db


class FindingStore:
    """CRUD operations for findings"""

    def __init__(self):
        self.db = get_db()

    def create(self, finding: Finding) -> Finding:
        """Create a new finding"""
        self.db.execute(
            """
            INSERT INTO findings (
                id, title, severity, confidence, description,
                evidence_safe, affected_assets, remediation, refs,
                status, discovered_by, task_id, run_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.id,
                finding.title,
                finding.severity.value,
                finding.confidence.value,
                finding.description,
                json.dumps(finding.evidence_safe),
                json.dumps(finding.affected_assets),
                finding.remediation,
                json.dumps(finding.references),
                finding.status.value,
                finding.discovered_by,
                finding.task_id,
                finding.run_id,
                finding.created_at,
                finding.updated_at
            )
        )
        return finding

    def get(self, finding_id: str) -> Optional[Finding]:
        """Get finding by ID"""
        row = self.db.fetchone("SELECT * FROM findings WHERE id = ?", (finding_id,))
        if not row:
            return None
        return self._row_to_finding(row)

    def list(
        self,
        severity: Optional[Severity] = None,
        status: Optional[FindingStatus] = None,
        limit: int = 100
    ) -> List[Finding]:
        """List findings with optional filters"""
        query = "SELECT * FROM findings WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity.value)

        if status:
            query += " AND status = ?"
            params.append(status.value)

        query += " ORDER BY CASE severity "
        query += "WHEN 'critical' THEN 1 "
        query += "WHEN 'high' THEN 2 "
        query += "WHEN 'medium' THEN 3 "
        query += "WHEN 'low' THEN 4 "
        query += "ELSE 5 END, created_at DESC LIMIT ?"
        params.append(limit)

        rows = self.db.fetchall(query, tuple(params))
        return [self._row_to_finding(row) for row in rows]

    def update(self, finding_id: str, **kwargs) -> Optional[Finding]:
        """Update finding fields"""
        set_clauses = []
        params = []

        for key, value in kwargs.items():
            # Map 'references' to 'refs' for SQL
            if key == 'references':
                key = 'refs'
            if key in ['evidence_safe', 'affected_assets', 'refs']:
                value = json.dumps(value)
            elif hasattr(value, 'value'):
                value = value.value
            set_clauses.append(f"{key} = ?")
            params.append(value)

        params.append(finding_id)

        query = f"UPDATE findings SET {', '.join(set_clauses)} WHERE id = ?"
        self.db.execute(query, tuple(params))

        return self.get(finding_id)

    def _row_to_finding(self, row) -> Finding:
        """Convert database row to Finding"""
        return Finding(
            id=row['id'],
            title=row['title'],
            severity=row['severity'],
            confidence=row['confidence'],
            description=row['description'],
            evidence_safe=json.loads(row['evidence_safe']) if row['evidence_safe'] else {},
            affected_assets=json.loads(row['affected_assets']) if row['affected_assets'] else [],
            remediation=row['remediation'],
            references=json.loads(row['refs']) if row['refs'] else [],  # Use 'refs' column
            status=row['status'],
            discovered_by=row['discovered_by'],
            task_id=row['task_id'],
            run_id=row['run_id'],
            created_at=row['created_at'],
            updated_at=row['updated_at']
        )


class CodeFindingStore:
    """CRUD operations for code findings"""

    def __init__(self):
        self.db = get_db()

    def create(self, finding: CodeFinding) -> CodeFinding:
        """Create a new code finding"""
        self.db.execute(
            """
            INSERT INTO code_findings (
                id, title, severity, confidence, file_path, line_ranges,
                snippet_safe, reasoning, remediation, cwe_id, owasp_category,
                status, discovered_by, task_id, run_id, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                finding.id,
                finding.title,
                finding.severity.value,
                finding.confidence.value,
                finding.file_path,
                json.dumps(finding.line_ranges),
                finding.snippet_safe,
                finding.reasoning,
                finding.remediation,
                finding.cwe_id,
                finding.owasp_category,
                finding.status.value,
                finding.discovered_by,
                finding.task_id,
                finding.run_id,
                finding.created_at,
                finding.updated_at
            )
        )
        return finding

    def get(self, finding_id: str) -> Optional[CodeFinding]:
        """Get code finding by ID"""
        row = self.db.fetchone("SELECT * FROM code_findings WHERE id = ?", (finding_id,))
        if not row:
            return None
        return self._row_to_code_finding(row)

    def list(
        self,
        severity: Optional[CodeSeverity] = None,
        status: Optional[CodeFindingStatus] = None,
        limit: int = 100
    ) -> List[CodeFinding]:
        """List code findings with optional filters"""
        query = "SELECT * FROM code_findings WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity.value)

        if status:
            query += " AND status = ?"
            params.append(status.value)

        query += " ORDER BY CASE severity "
        query += "WHEN 'critical' THEN 1 "
        query += "WHEN 'high' THEN 2 "
        query += "WHEN 'medium' THEN 3 "
        query += "WHEN 'low' THEN 4 "
        query += "ELSE 5 END, created_at DESC LIMIT ?"
        params.append(limit)

        rows = self.db.fetchall(query, tuple(params))
        return [self._row_to_code_finding(row) for row in rows]

    def _row_to_code_finding(self, row) -> CodeFinding:
        """Convert database row to CodeFinding"""
        return CodeFinding(
            id=row['id'],
            title=row['title'],
            severity=row['severity'],
            confidence=row['confidence'],
            file_path=row['file_path'],
            line_ranges=json.loads(row['line_ranges']),
            snippet_safe=row['snippet_safe'],
            reasoning=row['reasoning'],
            remediation=row['remediation'],
            cwe_id=row['cwe_id'],
            owasp_category=row['owasp_category'],
            status=row['status'],
            discovered_by=row['discovered_by'],
            task_id=row['task_id'],
            run_id=row['run_id'],
            created_at=row['created_at'],
            updated_at=row['updated_at']
        )
