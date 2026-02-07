"""Artifact storage and indexing operations"""
import json
from typing import List, Optional
from pathlib import Path
import hashlib

from ..schemas.artifact import ArtifactIndex, ArtifactType
from .database import get_db


class ArtifactStore:
    """CRUD operations for artifacts"""

    def __init__(self):
        self.db = get_db()

    def create(self, artifact: ArtifactIndex) -> ArtifactIndex:
        """Register a new artifact"""
        self.db.execute(
            """
            INSERT INTO artifacts (
                artifact_id, type, path, produced_by, related_task_id,
                related_run_id, hash, size_bytes, metadata, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                artifact.artifact_id,
                artifact.type.value,
                artifact.path,
                artifact.produced_by,
                artifact.related_task_id,
                artifact.related_run_id,
                artifact.hash,
                artifact.size_bytes,
                json.dumps(artifact.metadata),
                artifact.created_at
            )
        )
        return artifact

    def get(self, artifact_id: str) -> Optional[ArtifactIndex]:
        """Get artifact by ID"""
        row = self.db.fetchone("SELECT * FROM artifacts WHERE artifact_id = ?", (artifact_id,))
        if not row:
            return None
        return self._row_to_artifact(row)

    def list(
        self,
        artifact_type: Optional[ArtifactType] = None,
        produced_by: Optional[str] = None,
        task_id: Optional[str] = None,
        run_id: Optional[str] = None,
        limit: int = 100
    ) -> List[ArtifactIndex]:
        """List artifacts with optional filters"""
        query = "SELECT * FROM artifacts WHERE 1=1"
        params = []

        if artifact_type:
            query += " AND type = ?"
            params.append(artifact_type.value)

        if produced_by:
            query += " AND produced_by = ?"
            params.append(produced_by)

        if task_id:
            query += " AND related_task_id = ?"
            params.append(task_id)

        if run_id:
            query += " AND related_run_id = ?"
            params.append(run_id)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = self.db.fetchall(query, tuple(params))
        return [self._row_to_artifact(row) for row in rows]

    def register_file(
        self,
        file_path: Path,
        artifact_type: ArtifactType,
        produced_by: str,
        task_id: Optional[str] = None,
        run_id: Optional[str] = None,
        metadata: Optional[dict] = None
    ) -> ArtifactIndex:
        """Register a file as an artifact (convenience method)"""
        # Calculate hash
        hash_obj = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        file_hash = f"sha256:{hash_obj.hexdigest()}"

        # Get file size
        size_bytes = file_path.stat().st_size

        # Generate artifact ID
        artifact_id = f"artifact_{hash_obj.hexdigest()[:12]}"

        artifact = ArtifactIndex(
            artifact_id=artifact_id,
            type=artifact_type,
            path=str(file_path),
            produced_by=produced_by,
            related_task_id=task_id,
            related_run_id=run_id,
            hash=file_hash,
            size_bytes=size_bytes,
            metadata=metadata or {}
        )

        return self.create(artifact)

    def _row_to_artifact(self, row) -> ArtifactIndex:
        """Convert database row to ArtifactIndex"""
        return ArtifactIndex(
            artifact_id=row['artifact_id'],
            type=row['type'],
            path=row['path'],
            produced_by=row['produced_by'],
            related_task_id=row['related_task_id'],
            related_run_id=row['related_run_id'],
            hash=row['hash'],
            size_bytes=row['size_bytes'],
            metadata=json.loads(row['metadata']) if row['metadata'] else {},
            created_at=row['created_at']
        )
