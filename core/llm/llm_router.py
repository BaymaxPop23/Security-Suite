"""Intelligent LLM routing based on task complexity"""
from typing import Optional, Dict, Any, List, Literal
from enum import Enum

from core.llm.ollama_client import get_ollama_client, OllamaClient
from core.llm.claude_client import get_claude_client, ClaudeClient
from core.schemas.task import TaskType


class TaskComplexity(Enum):
    """Task complexity levels"""
    SIMPLE = "simple"          # Pattern matching, tool execution, basic reasoning
    MODERATE = "moderate"      # Code review, vulnerability analysis
    COMPLEX = "complex"        # Planning, architecture analysis, complex reasoning
    VERY_COMPLEX = "very_complex"  # Multi-step reasoning, report generation


class LLMRouter:
    """
    Routes LLM requests to appropriate provider based on task complexity

    Routing strategy:
    - SIMPLE: Ollama llama3.1:8b (fastest)
    - MODERATE: Ollama llama3.1:8b or Claude Haiku
    - COMPLEX: Ollama llama3.1:70b or Claude Sonnet
    - VERY_COMPLEX: Claude Sonnet (best reasoning)

    Falls back gracefully if preferred provider unavailable
    """

    def __init__(self, prefer_claude: bool = False):
        self.prefer_claude = prefer_claude
        self.ollama_client = get_ollama_client()
        self.claude_client = get_claude_client()

        # Check availability
        self.ollama_available = self.ollama_client.check_health()
        self.claude_available = self.claude_client.is_available()

    def _determine_complexity(
        self,
        task_type: Optional[TaskType] = None,
        prompt_length: Optional[int] = None,
        requires_reasoning: bool = True,
        custom_complexity: Optional[TaskComplexity] = None
    ) -> TaskComplexity:
        """
        Determine task complexity based on various factors

        Args:
            task_type: Type of task (planning, recon, etc.)
            prompt_length: Length of prompt in characters
            requires_reasoning: Whether task requires deep reasoning
            custom_complexity: Override with explicit complexity

        Returns:
            TaskComplexity level
        """
        if custom_complexity:
            return custom_complexity

        # Task type based complexity
        if task_type:
            complexity_map = {
                TaskType.PLANNING: TaskComplexity.VERY_COMPLEX,
                TaskType.REPORTING: TaskComplexity.COMPLEX,
                TaskType.CODE_REVIEW: TaskComplexity.MODERATE,
                TaskType.SECURITY_TESTING: TaskComplexity.MODERATE,
                TaskType.APK_ANALYSIS: TaskComplexity.MODERATE,
                TaskType.RECON: TaskComplexity.SIMPLE,
            }
            if task_type in complexity_map:
                base_complexity = complexity_map[task_type]
            else:
                base_complexity = TaskComplexity.MODERATE
        else:
            base_complexity = TaskComplexity.MODERATE

        # Adjust based on prompt length
        if prompt_length:
            if prompt_length > 10000 and base_complexity == TaskComplexity.MODERATE:
                base_complexity = TaskComplexity.COMPLEX
            elif prompt_length > 20000:
                base_complexity = TaskComplexity.COMPLEX

        # Adjust based on reasoning requirement
        if not requires_reasoning and base_complexity == TaskComplexity.MODERATE:
            base_complexity = TaskComplexity.SIMPLE

        return base_complexity

    def _select_provider_and_model(
        self,
        complexity: TaskComplexity
    ) -> tuple[Literal["ollama", "claude"], str]:
        """
        Select provider and model based on complexity and availability

        Args:
            complexity: Task complexity level

        Returns:
            Tuple of (provider, model_name)
        """
        # Define routing preferences
        # Note: Claude CLI has limitations for programmatic use, so prefer Ollama when available
        routing_table = {
            TaskComplexity.SIMPLE: [
                ("ollama", "llama3.1:8b"),
                ("ollama", "llama3.2:latest"),
                ("claude", "claude-haiku-4.5"),  # True fallback only
            ],
            TaskComplexity.MODERATE: [
                ("ollama", "llama3.1:8b"),
                ("ollama", "codellama:7b"),
                ("ollama", "codellama:latest"),
                ("claude", "claude-haiku-4.5"),  # True fallback only
            ],
            TaskComplexity.COMPLEX: [
                ("ollama", "llama3.1:70b"),
                ("ollama", "llama3.1:8b"),  # Fallback to smaller model
                ("ollama", "llama3.2:latest"),
                ("claude", "claude-sonnet-4.5"),  # True fallback only
            ],
            TaskComplexity.VERY_COMPLEX: [
                ("ollama", "llama3.1:70b"),
                ("ollama", "llama3.1:8b"),  # Fallback to smaller model
                ("claude", "claude-sonnet-4.5"),  # True fallback only
                ("claude", "claude-opus-4.6"),
            ]
        }

        preferences = routing_table.get(complexity, routing_table[TaskComplexity.MODERATE])

        # If prefer_claude is set, move claude options to front
        if self.prefer_claude:
            preferences = sorted(preferences, key=lambda x: 0 if x[0] == "claude" else 1)

        # Find first available option
        for provider, model in preferences:
            if provider == "ollama" and self.ollama_available:
                # Check if specific model is available
                available_models = self.ollama_client.list_models()
                if model in available_models or not available_models:  # Empty list means no check
                    return ("ollama", model)
            elif provider == "claude" and self.claude_available:
                return ("claude", model)

        # If nothing available, raise error
        if not self.ollama_available and not self.claude_available:
            raise Exception(
                "No LLM providers available. "
                "Start Ollama with 'ollama serve' or ensure Claude CLI is installed."
            )

        # Final fallback
        if self.ollama_available:
            return ("ollama", "llama3.1:8b")
        else:
            return ("claude", "claude-sonnet-4.5")

    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.1,
        task_type: Optional[TaskType] = None,
        complexity: Optional[TaskComplexity] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate completion with automatic provider routing

        Args:
            prompt: User prompt
            system: System prompt
            temperature: Sampling temperature
            task_type: Task type for complexity determination
            complexity: Override complexity level
            **kwargs: Additional parameters

        Returns:
            Dict with 'response' and metadata including 'provider' and 'model'
        """
        # Determine complexity
        prompt_length = len(prompt) + (len(system) if system else 0)
        task_complexity = self._determine_complexity(
            task_type=task_type,
            prompt_length=prompt_length,
            custom_complexity=complexity
        )

        # Select provider and model
        provider, model = self._select_provider_and_model(task_complexity)

        # Route to appropriate client
        if provider == "ollama":
            result = self.ollama_client.generate(
                prompt=prompt,
                system=system,
                model=model,
                temperature=temperature,
                **kwargs
            )
            result["provider"] = "ollama"
            result["complexity"] = task_complexity.value if hasattr(task_complexity, 'value') else str(task_complexity)
            return result
        else:  # claude
            try:
                result = self.claude_client.generate(
                    prompt=prompt,
                    system=system,
                    temperature=temperature,
                    model=model,
                    **kwargs
                )
                result["provider"] = "claude"
                result["complexity"] = task_complexity.value if hasattr(task_complexity, 'value') else str(task_complexity)
                return result
            except Exception as e:
                # Fall back to Ollama if Claude fails
                print(f"⚠️  Claude generation failed: {e}. Falling back to Ollama.")
                if self.ollama_available:
                    result = self.ollama_client.generate(
                        prompt=prompt,
                        system=system,
                        model="llama3.1:8b",
                        temperature=temperature,
                        **kwargs
                    )
                    result["provider"] = "ollama"
                    result["fallback"] = True
                    result["complexity"] = task_complexity.value if hasattr(task_complexity, 'value') else str(task_complexity)
                    return result
                else:
                    raise Exception("Both Claude and Ollama are unavailable")

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        task_type: Optional[TaskType] = None,
        complexity: Optional[TaskComplexity] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Chat completion with automatic provider routing

        Args:
            messages: List of message dicts with 'role' and 'content'
            temperature: Sampling temperature
            task_type: Task type for complexity determination
            complexity: Override complexity level
            **kwargs: Additional parameters

        Returns:
            Dict with 'message' and metadata
        """
        # Calculate total message length
        total_length = sum(len(msg.get("content", "")) for msg in messages)

        task_complexity = self._determine_complexity(
            task_type=task_type,
            prompt_length=total_length,
            custom_complexity=complexity
        )

        provider, model = self._select_provider_and_model(task_complexity)

        if provider == "ollama":
            result = self.ollama_client.chat(
                messages=messages,
                model=model,
                temperature=temperature,
                **kwargs
            )
            result["provider"] = "ollama"
            result["complexity"] = task_complexity.value if hasattr(task_complexity, 'value') else str(task_complexity)
            return result
        else:  # claude
            try:
                result = self.claude_client.chat(
                    messages=messages,
                    temperature=temperature,
                    model=model,
                    **kwargs
                )
                result["provider"] = "claude"
                result["complexity"] = task_complexity.value if hasattr(task_complexity, 'value') else str(task_complexity)
                return result
            except Exception as e:
                # Fall back to Ollama if Claude fails
                print(f"⚠️  Claude chat failed: {e}. Falling back to Ollama.")
                if self.ollama_available:
                    result = self.ollama_client.chat(
                        messages=messages,
                        model="llama3.1:8b",
                        temperature=temperature,
                        **kwargs
                    )
                    result["provider"] = "ollama"
                    result["fallback"] = True
                    result["complexity"] = task_complexity.value if hasattr(task_complexity, 'value') else str(task_complexity)
                    return result
                else:
                    raise Exception("Both Claude and Ollama are unavailable")

    def generate_json(
        self,
        prompt: str,
        system: Optional[str] = None,
        task_type: Optional[TaskType] = None,
        complexity: Optional[TaskComplexity] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate JSON response with automatic provider routing

        Args:
            prompt: User prompt
            system: System prompt
            task_type: Task type for complexity determination
            complexity: Override complexity level
            **kwargs: Additional parameters

        Returns:
            Parsed JSON response
        """
        prompt_length = len(prompt) + (len(system) if system else 0)
        task_complexity = self._determine_complexity(
            task_type=task_type,
            prompt_length=prompt_length,
            custom_complexity=complexity
        )

        provider, model = self._select_provider_and_model(task_complexity)

        if provider == "ollama":
            return self.ollama_client.generate_json(
                prompt=prompt,
                system=system,
                model=model,
                **kwargs
            )
        else:  # claude
            return self.claude_client.generate_json(
                prompt=prompt,
                system=system,
                model=model,
                **kwargs
            )

    def get_status(self) -> Dict[str, Any]:
        """Get router status including provider availability"""
        return {
            "ollama": {
                "available": self.ollama_available,
                "models": self.ollama_client.list_models() if self.ollama_available else []
            },
            "claude": {
                "available": self.claude_available,
                "version": self.claude_client.get_version() if self.claude_available else None
            },
            "prefer_claude": self.prefer_claude
        }


# Global router instance
_router = None

def get_llm_router(prefer_claude: bool = False) -> LLMRouter:
    """Get or create global LLM router"""
    global _router
    if _router is None:
        _router = LLMRouter(prefer_claude=prefer_claude)
    return _router
