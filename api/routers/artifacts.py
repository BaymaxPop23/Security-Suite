"""Artifact endpoints"""
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import List, Optional
from pathlib import Path

from core.schemas import ArtifactIndex, ArtifactType
from core.storage.artifact_store import ArtifactStore

router = APIRouter()


class ArtifactResponse(BaseModel):
    """Artifact response"""
    artifact_id: str
    type: str
    path: str
    produced_by: str
    size_bytes: Optional[int]
    created_at: str


@router.get("/artifacts")
async def list_artifacts(
    artifact_type: Optional[ArtifactType] = Query(None),
    produced_by: Optional[str] = Query(None),
    limit: int = Query(100, le=1000)
) -> List[ArtifactResponse]:
    """List artifacts with optional filters"""
    try:
        artifact_store = ArtifactStore()
        artifacts = artifact_store.list(
            artifact_type=artifact_type,
            produced_by=produced_by,
            limit=limit
        )

        return [
            ArtifactResponse(
                artifact_id=a.artifact_id,
                type=a.type.value,
                path=a.path,
                produced_by=a.produced_by,
                size_bytes=a.size_bytes,
                created_at=str(a.created_at)
            )
            for a in artifacts
        ]

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/artifacts/{artifact_id}")
async def get_artifact(artifact_id: str):
    """Download an artifact file"""
    try:
        artifact_store = ArtifactStore()
        artifact = artifact_store.get(artifact_id)

        if not artifact:
            raise HTTPException(status_code=404, detail="Artifact not found")

        file_path = Path(artifact.path)

        if not file_path.exists():
            raise HTTPException(status_code=404, detail="Artifact file not found")

        return FileResponse(file_path)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
