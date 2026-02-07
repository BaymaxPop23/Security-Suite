"""Ollama LLM client wrapper for all agent reasoning"""
import json
from typing import Optional, List, Dict, Any
import httpx
from datetime import datetime

from core.schemas.health import HealthCheckResult


class OllamaClient:
    """
    Unified Ollama client for all agents
    Handles model selection, retries, timeouts, and deterministic settings
    """

    def __init__(
        self,
        base_url: str = "http://localhost:11434",
        default_model: str = "llama3.1:8b",
        timeout: int = 120,
        max_retries: int = 3
    ):
        self.base_url = base_url.rstrip('/')
        self.default_model = default_model
        self.timeout = timeout
        self.max_retries = max_retries

    def generate(
        self,
        prompt: str,
        model: Optional[str] = None,
        system: Optional[str] = None,
        temperature: float = 0.1,
        stream: bool = False,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate completion from Ollama

        Args:
            prompt: User prompt
            model: Model to use (defaults to configured default)
            system: System prompt
            temperature: Sampling temperature (0.0 = deterministic)
            stream: Whether to stream response
            **kwargs: Additional Ollama parameters

        Returns:
            Dict with 'response' and metadata
        """
        model = model or self.default_model

        payload = {
            "model": model,
            "prompt": prompt,
            "stream": stream,
            "options": {
                "temperature": temperature,
                "num_predict": kwargs.get("max_tokens", 2048),
                **kwargs.get("options", {})
            }
        }

        if system:
            payload["system"] = system

        # Add format if specified (for JSON output)
        if kwargs.get("format") == "json":
            payload["format"] = "json"

        for attempt in range(self.max_retries):
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.post(
                        f"{self.base_url}/api/generate",
                        json=payload
                    )
                    response.raise_for_status()

                    result = response.json()

                    return {
                        "response": result.get("response", ""),
                        "model": result.get("model", model),
                        "created_at": result.get("created_at"),
                        "done": result.get("done", True),
                        "context": result.get("context"),
                        "total_duration": result.get("total_duration"),
                        "load_duration": result.get("load_duration"),
                        "prompt_eval_count": result.get("prompt_eval_count"),
                        "eval_count": result.get("eval_count")
                    }

            except httpx.TimeoutException:
                if attempt < self.max_retries - 1:
                    continue
                raise Exception(f"Ollama request timed out after {self.timeout}s")

            except httpx.HTTPError as e:
                if attempt < self.max_retries - 1:
                    continue
                raise Exception(f"Ollama HTTP error: {str(e)}")

            except Exception as e:
                if attempt < self.max_retries - 1:
                    continue
                raise Exception(f"Ollama error: {str(e)}")

    def chat(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.1,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Chat completion using messages format

        Args:
            messages: List of message dicts with 'role' and 'content'
            model: Model to use
            temperature: Sampling temperature
            **kwargs: Additional parameters

        Returns:
            Dict with 'message' and metadata
        """
        model = model or self.default_model

        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
                **kwargs.get("options", {})
            }
        }

        if kwargs.get("format") == "json":
            payload["format"] = "json"

        for attempt in range(self.max_retries):
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    response = client.post(
                        f"{self.base_url}/api/chat",
                        json=payload
                    )
                    response.raise_for_status()

                    result = response.json()

                    return {
                        "message": result.get("message", {}),
                        "model": result.get("model", model),
                        "created_at": result.get("created_at"),
                        "done": result.get("done", True),
                        "total_duration": result.get("total_duration"),
                        "prompt_eval_count": result.get("prompt_eval_count"),
                        "eval_count": result.get("eval_count")
                    }

            except Exception as e:
                if attempt < self.max_retries - 1:
                    continue
                raise Exception(f"Ollama chat error: {str(e)}")

    def generate_json(
        self,
        prompt: str,
        model: Optional[str] = None,
        system: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate JSON response (forces JSON output format)

        Args:
            prompt: User prompt
            model: Model to use
            system: System prompt
            **kwargs: Additional parameters

        Returns:
            Parsed JSON response
        """
        result = self.generate(
            prompt=prompt,
            model=model,
            system=system,
            format="json",
            **kwargs
        )

        try:
            return json.loads(result["response"])
        except json.JSONDecodeError:
            # Fallback: try to extract JSON from response
            response_text = result["response"]
            # Look for JSON in markdown code blocks
            if "```json" in response_text:
                json_start = response_text.find("```json") + 7
                json_end = response_text.find("```", json_start)
                response_text = response_text[json_start:json_end].strip()
            return json.loads(response_text)

    def check_health(self) -> bool:
        """Check if Ollama is running and accessible (simple boolean check)"""
        try:
            with httpx.Client(timeout=5) as client:
                response = client.get(f"{self.base_url}/api/tags")
                return response.status_code == 200
        except:
            return False

    def health_check(self, required_models: Optional[List[str]] = None) -> HealthCheckResult:
        """
        Comprehensive health check for Ollama

        Args:
            required_models: List of required models (e.g., ['llama3.1:8b', 'llama3.1:70b'])

        Returns:
            HealthCheckResult with detailed status
        """
        if required_models is None:
            required_models = ["llama3.1:8b"]

        recommendations = []
        error_message = None

        # Check if Ollama is running
        try:
            with httpx.Client(timeout=5) as client:
                response = client.get(f"{self.base_url}/api/tags")
                response.raise_for_status()

                data = response.json()
                available_models = [model["name"] for model in data.get("models", [])]

                # Check for missing required models
                missing_models = [m for m in required_models if m not in available_models]

                # Determine status
                if not missing_models:
                    status = "healthy"
                elif available_models:
                    status = "degraded"
                    error_message = f"Missing required models: {', '.join(missing_models)}"
                    for model in missing_models:
                        recommendations.append(f"Pull model: ollama pull {model}")
                else:
                    status = "degraded"
                    error_message = "No models available"
                    recommendations.append("Pull a model: ollama pull llama3.1:8b")

                # Check Claude availability
                from core.llm.claude_client import get_claude_client
                claude_client = get_claude_client()
                claude_available = claude_client.is_available()
                claude_version = claude_client.get_version() if claude_available else None

                return HealthCheckResult(
                    status=status,
                    ollama_running=True,
                    ollama_url=self.base_url,
                    available_models=available_models,
                    missing_models=missing_models,
                    error_message=error_message,
                    recommendations=recommendations,
                    claude_available=claude_available,
                    claude_version=claude_version
                )

        except httpx.ConnectError:
            error_message = f"Cannot connect to Ollama at {self.base_url}"
            recommendations.extend([
                "Start Ollama: ollama serve",
                "Or check if running on different port",
                "Verify firewall settings"
            ])

            # Check if Claude is available as fallback
            from core.llm.claude_client import get_claude_client
            claude_client = get_claude_client()
            claude_available = claude_client.is_available()
            claude_version = claude_client.get_version() if claude_available else None

            if claude_available:
                status = "degraded"
                error_message += " (Claude CLI available as fallback)"
            else:
                status = "down"
                recommendations.append("Alternative: Install Claude CLI for fallback reasoning")

            return HealthCheckResult(
                status=status,
                ollama_running=False,
                ollama_url=self.base_url,
                available_models=[],
                missing_models=required_models,
                error_message=error_message,
                recommendations=recommendations,
                claude_available=claude_available,
                claude_version=claude_version
            )

        except Exception as e:
            error_message = f"Ollama health check failed: {str(e)}"
            recommendations.append("Check Ollama service status")

            return HealthCheckResult(
                status="down",
                ollama_running=False,
                ollama_url=self.base_url,
                available_models=[],
                missing_models=required_models,
                error_message=error_message,
                recommendations=recommendations,
                claude_available=False
            )

    def list_models(self) -> List[str]:
        """List available models"""
        try:
            with httpx.Client(timeout=10) as client:
                response = client.get(f"{self.base_url}/api/tags")
                response.raise_for_status()
                data = response.json()
                return [model["name"] for model in data.get("models", [])]
        except:
            return []


# Global client instance
_client = None

def get_ollama_client(
    model: Optional[str] = None,
    base_url: str = "http://localhost:11434"
) -> OllamaClient:
    """Get or create global Ollama client"""
    global _client
    if _client is None:
        _client = OllamaClient(base_url=base_url, default_model=model or "llama3.1:8b")
    return _client
