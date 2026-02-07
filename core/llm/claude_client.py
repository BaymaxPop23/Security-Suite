"""Claude Code (terminal) client for LLM reasoning"""
import subprocess
import json
import shutil
from typing import Optional, Dict, Any, List
from pathlib import Path


class ClaudeClient:
    """
    Client for Claude Code CLI (terminal)
    Uses the 'claude' command-line tool for reasoning
    """

    def __init__(self, timeout: int = 300):
        self.timeout = timeout
        self._check_availability()

    def _check_availability(self) -> bool:
        """Check if claude CLI is available"""
        return shutil.which("claude") is not None

    def is_available(self) -> bool:
        """Check if Claude CLI is available and working"""
        if not self._check_availability():
            return False

        try:
            result = subprocess.run(
                ["claude", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False

    def get_version(self) -> Optional[str]:
        """Get Claude CLI version"""
        try:
            result = subprocess.run(
                ["claude", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return None
        except Exception:
            return None

    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate completion using Claude CLI

        Args:
            prompt: User prompt
            system: System prompt (prepended to prompt)
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            **kwargs: Additional parameters

        Returns:
            Dict with 'response' and metadata
        """
        if not self.is_available():
            raise Exception("Claude CLI not available. Install with: npm install -g @anthropic-ai/claude-code")

        # Construct full prompt
        full_prompt = prompt
        if system:
            full_prompt = f"{system}\n\n{prompt}"

        # Create temporary file for complex prompts
        temp_file = None
        try:
            # Use stdin for prompt - Claude Code CLI accepts direct input
            cmd = ["claude"]

            # Add model specification if provided
            if "model" in kwargs:
                cmd.extend(["--model", kwargs["model"]])

            result = subprocess.run(
                cmd,
                input=full_prompt,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            if result.returncode != 0:
                raise Exception(f"Claude CLI error: {result.stderr}")

            response = result.stdout.strip()

            return {
                "response": response,
                "model": kwargs.get("model", "claude-sonnet-4.5"),
                "provider": "claude",
                "done": True
            }

        except subprocess.TimeoutExpired:
            raise Exception(f"Claude CLI timed out after {self.timeout}s")
        except Exception as e:
            raise Exception(f"Claude CLI error: {str(e)}")

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.1,
        max_tokens: int = 4096,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Chat completion using messages format

        Args:
            messages: List of message dicts with 'role' and 'content'
            temperature: Sampling temperature
            max_tokens: Maximum tokens
            **kwargs: Additional parameters

        Returns:
            Dict with 'message' and metadata
        """
        # Convert messages to single prompt
        prompt_parts = []
        system_prompt = None

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")

            if role == "system":
                system_prompt = content
            elif role == "user":
                prompt_parts.append(f"User: {content}")
            elif role == "assistant":
                prompt_parts.append(f"Assistant: {content}")

        prompt = "\n\n".join(prompt_parts)

        result = self.generate(
            prompt=prompt,
            system=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs
        )

        return {
            "message": {
                "role": "assistant",
                "content": result["response"]
            },
            "model": result.get("model"),
            "provider": "claude",
            "done": True
        }

    def generate_json(
        self,
        prompt: str,
        system: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Generate JSON response

        Args:
            prompt: User prompt (should instruct to return JSON)
            system: System prompt
            **kwargs: Additional parameters

        Returns:
            Parsed JSON response
        """
        # Add JSON instruction to prompt
        json_prompt = f"{prompt}\n\nIMPORTANT: Respond ONLY with valid JSON. No markdown, no code blocks, just pure JSON."

        result = self.generate(
            prompt=json_prompt,
            system=system,
            **kwargs
        )

        response_text = result["response"]

        try:
            # Try direct parse
            return json.loads(response_text)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code blocks
            if "```json" in response_text:
                json_start = response_text.find("```json") + 7
                json_end = response_text.find("```", json_start)
                response_text = response_text[json_start:json_end].strip()
            elif "```" in response_text:
                json_start = response_text.find("```") + 3
                json_end = response_text.find("```", json_start)
                response_text = response_text[json_start:json_end].strip()

            return json.loads(response_text)


# Global client instance
_claude_client = None

def get_claude_client() -> ClaudeClient:
    """Get or create global Claude client"""
    global _claude_client
    if _claude_client is None:
        _claude_client = ClaudeClient()
    return _claude_client
