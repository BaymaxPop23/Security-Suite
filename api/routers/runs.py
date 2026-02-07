"""Run management endpoints"""
from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
import json

from orchestrator.run_manager import RunManager

router = APIRouter()


class RunStart(BaseModel):
    """Run start request - simplified for domains and APKs"""
    domains: List[str] = []
    apks: List[str] = []
    dry_run: bool = False


class RunStatusResponse(BaseModel):
    """Run status response"""
    run_id: str
    status: str
    started_at: str
    completed_at: Optional[str]
    total_tasks: int
    task_status: Dict[str, int]
    scope: Dict[str, Any]


@router.post("/runs/start")
async def start_run(
    request: RunStart,
    background_tasks: BackgroundTasks
) -> Dict[str, Any]:
    """
    Start a new security assessment run

    Provide domains for EASD reconnaissance or APKs for security analysis
    """
    try:
        # Create scope from request
        scope = {
            "domains": request.domains,
            "apks": request.apks
        }

        run_manager = RunManager(dry_run=request.dry_run)
        run_id = run_manager.start_run(scope)

        # Execute run in background
        background_tasks.add_task(run_manager.execute_run, run_id)

        return {
            "run_id": run_id,
            "status": "started",
            "message": f"Run started with {len(request.domains)} domains and {len(request.apks)} APKs"
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/runs")
async def list_runs() -> Dict[str, Any]:
    """List all runs"""
    try:
        from pathlib import Path
        runs_dir = Path("runs")

        if not runs_dir.exists():
            return {"runs": []}

        runs = []
        for run_dir in runs_dir.iterdir():
            if run_dir.is_dir():
                metadata_file = run_dir / "metadata.json"
                if metadata_file.exists():
                    with open(metadata_file, 'r') as f:
                        metadata = json.load(f)
                        runs.append(metadata)

        # Sort by started_at descending
        runs.sort(key=lambda x: x.get('started_at', ''), reverse=True)

        return {"runs": runs}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/runs/{run_id}")
async def get_run_status(run_id: str) -> RunStatusResponse:
    """Get status of a specific run"""
    try:
        run_manager = RunManager()
        status = run_manager.get_run_status(run_id)

        if "error" in status:
            raise HTTPException(status_code=404, detail=status["error"])

        return RunStatusResponse(**status)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
