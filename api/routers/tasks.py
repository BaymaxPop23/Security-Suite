"""Task management endpoints"""
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

from core.schemas import Task, TaskStatus, TaskPriority
from core.storage.task_store import TaskStore

router = APIRouter()


class TaskUpdate(BaseModel):
    """Task update request"""
    status: Optional[TaskStatus] = None
    priority: Optional[TaskPriority] = None
    assignee_agent: Optional[str] = None


class TaskResponse(BaseModel):
    """Task response"""
    id: str
    title: str
    type: str
    priority: str
    status: str
    assignee_agent: Optional[str]
    created_at: datetime
    updated_at: datetime


@router.get("/tasks")
async def list_tasks(
    status: Optional[TaskStatus] = Query(None),
    assignee: Optional[str] = Query(None),
    limit: int = Query(100, le=1000)
) -> List[TaskResponse]:
    """List tasks with optional filters"""
    try:
        task_store = TaskStore()
        tasks = task_store.list(status=status, assignee=assignee, limit=limit)

        return [
            TaskResponse(
                id=t.id,
                title=t.title,
                type=t.type.value,
                priority=t.priority.value,
                status=t.status.value,
                assignee_agent=t.assignee_agent,
                created_at=t.created_at,
                updated_at=t.updated_at
            )
            for t in tasks
        ]

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/tasks/{task_id}")
async def get_task(task_id: str) -> Task:
    """Get a specific task"""
    try:
        task_store = TaskStore()
        task = task_store.get(task_id)

        if not task:
            raise HTTPException(status_code=404, detail="Task not found")

        return task

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/tasks/{task_id}")
async def update_task(task_id: str, update: TaskUpdate) -> Task:
    """Update a task"""
    try:
        task_store = TaskStore()

        # Build update dict
        updates = {}
        if update.status is not None:
            updates['status'] = update.status
        if update.priority is not None:
            updates['priority'] = update.priority
        if update.assignee_agent is not None:
            updates['assignee_agent'] = update.assignee_agent

        task = task_store.update(task_id, **updates)

        if not task:
            raise HTTPException(status_code=404, detail="Task not found")

        return task

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
