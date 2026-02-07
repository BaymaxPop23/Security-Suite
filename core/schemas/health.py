"""Health check schemas"""
from typing import List, Optional, Literal
from pydantic import BaseModel, Field


class HealthCheckResult(BaseModel):
    """Result of system health check"""
    status: Literal["healthy", "degraded", "down"]
    ollama_running: bool
    ollama_url: str
    available_models: List[str] = Field(default_factory=list)
    missing_models: List[str] = Field(default_factory=list)
    error_message: Optional[str] = None
    recommendations: List[str] = Field(default_factory=list)

    # Claude terminal availability
    claude_available: bool = False
    claude_version: Optional[str] = None


class LLMProvider(BaseModel):
    """LLM provider information"""
    name: Literal["ollama", "claude"]
    available: bool
    models: List[str] = Field(default_factory=list)
    status: Literal["healthy", "degraded", "down"]
    error: Optional[str] = None
