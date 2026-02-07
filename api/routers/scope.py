"""Scope management endpoints"""
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any
import json

from core.storage.database import get_db

router = APIRouter()


class ScopeCreate(BaseModel):
    """Scope creation request"""
    scope_name: str
    in_scope: List[str]
    out_of_scope: List[str] = []


class ScopeResponse(BaseModel):
    """Scope response"""
    id: int
    scope_name: str
    in_scope: List[str]
    out_of_scope: List[str]
    created_at: str
    active: bool


@router.post("/scope")
async def create_scope(scope: ScopeCreate) -> ScopeResponse:
    """Create a new scope definition"""
    db = get_db()

    # Deactivate previous scopes
    db.execute("UPDATE scope SET active = 0")

    # Insert new scope
    cursor = db.execute(
        """
        INSERT INTO scope (scope_name, in_scope, out_of_scope, active)
        VALUES (?, ?, ?, 1)
        """,
        (
            scope.scope_name,
            json.dumps(scope.in_scope),
            json.dumps(scope.out_of_scope)
        )
    )

    # Get the inserted scope
    row = db.fetchone(
        "SELECT * FROM scope WHERE id = ?",
        (cursor.lastrowid,)
    )

    return ScopeResponse(
        id=row['id'],
        scope_name=row['scope_name'],
        in_scope=json.loads(row['in_scope']),
        out_of_scope=json.loads(row['out_of_scope']) if row['out_of_scope'] else [],
        created_at=row['created_at'],
        active=bool(row['active'])
    )


@router.get("/scope/active")
async def get_active_scope() -> ScopeResponse:
    """Get the currently active scope"""
    db = get_db()

    row = db.fetchone("SELECT * FROM scope WHERE active = 1")

    if not row:
        raise HTTPException(status_code=404, detail="No active scope found")

    return ScopeResponse(
        id=row['id'],
        scope_name=row['scope_name'],
        in_scope=json.loads(row['in_scope']),
        out_of_scope=json.loads(row['out_of_scope']) if row['out_of_scope'] else [],
        created_at=row['created_at'],
        active=bool(row['active'])
    )
