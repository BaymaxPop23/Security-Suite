"""Artifact tracking and registration"""
from pathlib import Path
from typing import Optional
from datetime import datetime

from ..schemas.artifact import ArtifactIndex, ArtifactType
from ..storage.artifact_store import ArtifactStore


class ArtifactTracker:
    """
    Helper for registering and tracking artifacts produced by agents
    """

    def __init__(self, agent_name: str, run_id: str):
        self.agent_name = agent_name
        self.run_id = run_id
        self.store = ArtifactStore()
        self.artifact_ids = []

    def register(
        self,
        file_path: Path,
        artifact_type: ArtifactType,
        task_id: Optional[str] = None,
        metadata: Optional[dict] = None
    ) -> ArtifactIndex:
        """
        Register an artifact file

        Args:
            file_path: Path to artifact file
            artifact_type: Type of artifact
            task_id: Optional task ID
            metadata: Optional metadata dict

        Returns:
            ArtifactIndex object
        """
        artifact = self.store.register_file(
            file_path=file_path,
            artifact_type=artifact_type,
            produced_by=self.agent_name,
            task_id=task_id,
            run_id=self.run_id,
            metadata=metadata
        )

        self.artifact_ids.append(artifact.artifact_id)
        return artifact

    def get_all(self) -> list:
        """Get all artifacts for this run"""
        return self.store.list(run_id=self.run_id)

    def get_artifact_ids(self) -> list:
        """Get list of artifact IDs produced in this run"""
        return self.artifact_ids
