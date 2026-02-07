"""Health check endpoints"""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any

from core.llm import get_ollama_client, get_llm_router
from core.schemas import HealthCheckResult

router = APIRouter()


@router.get("/health/ollama", response_model=HealthCheckResult)
async def ollama_health():
    """
    Check Ollama health status

    Returns comprehensive health check including:
    - Ollama running status
    - Available models
    - Missing required models
    - Claude CLI availability
    - Actionable recommendations
    """
    ollama_client = get_ollama_client()
    health = ollama_client.health_check(
        required_models=["llama3.1:8b", "llama3.1:70b", "codellama:7b"]
    )
    return health


@router.get("/health/llm")
async def llm_status():
    """
    Get overall LLM status (both Ollama and Claude)

    Returns status of all LLM providers and router configuration
    """
    router = get_llm_router()
    status = router.get_status()

    # Get detailed Ollama health
    ollama_client = get_ollama_client()
    ollama_health = ollama_client.health_check()

    return {
        "providers": status,
        "ollama_detailed": ollama_health.model_dump(),
        "system_status": ollama_health.status,
        "recommendations": ollama_health.recommendations
    }


@router.get("/health/system")
async def system_health():
    """
    Overall system health check

    Checks:
    - LLM services (Ollama + Claude)
    - Database connectivity
    - API status
    """
    # Check LLM
    ollama_client = get_ollama_client()
    llm_health = ollama_client.health_check()

    # Check database (simple check)
    try:
        from core.storage.database import get_db
        db = get_db()
        db.conn.execute("SELECT 1").fetchone()
        db_status = "healthy"
        db_error = None
    except Exception as e:
        db_status = "down"
        db_error = str(e)

    # Determine overall status
    if llm_health.status == "down" and not llm_health.claude_available:
        overall_status = "down"
    elif llm_health.status == "degraded" or db_status != "healthy":
        overall_status = "degraded"
    else:
        overall_status = "healthy"

    return {
        "status": overall_status,
        "components": {
            "llm": {
                "status": llm_health.status,
                "ollama_running": llm_health.ollama_running,
                "claude_available": llm_health.claude_available,
                "details": llm_health.model_dump()
            },
            "database": {
                "status": db_status,
                "error": db_error
            },
            "api": {
                "status": "healthy"
            }
        },
        "recommendations": llm_health.recommendations
    }
