"""Claude API Client - uses local API proxy"""
import requests
from typing import Optional, Dict, Any

class ClaudeAPIClient:
    """Client that uses the local Claude API proxy"""

    def __init__(self, base_url: str = "http://localhost:8000"):
        self.base_url = base_url

    def is_available(self) -> bool:
        """Check if Claude API is available"""
        try:
            response = requests.get(f"{self.base_url}/api/claude/status", timeout=2)
            return response.status_code == 200
        except:
            return False

    def generate(
        self,
        prompt: str,
        system: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: int = 2000,
        **kwargs
    ) -> Dict[str, Any]:
        """Generate response using Claude"""
        try:
            response = requests.post(
                f"{self.base_url}/api/claude/generate",
                json={
                    "prompt": prompt,
                    "system": system,
                    "temperature": temperature,
                    "max_tokens": max_tokens
                },
                timeout=120
            )

            if response.status_code == 200:
                return response.json()
            else:
                raise Exception(f"Claude API error: {response.status_code}")

        except Exception as e:
            raise Exception(f"Claude generation failed: {str(e)}")

def get_claude_api_client() -> ClaudeAPIClient:
    """Get Claude API client instance"""
    return ClaudeAPIClient()
