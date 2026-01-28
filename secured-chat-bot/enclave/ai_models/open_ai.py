"""
OpenAI platform integration.
"""

from typing import Tuple
from openai import OpenAI as OAClient

from .platform import Platform


class OpenAI(Platform):
    """OpenAI platform integration."""
    
    name = "openai"
    
    def __init__(self, api_key: str, base_url: str = None):
        """
        Initialize OpenAI client.
        
        Args:
            api_key: OpenAI API key.
            base_url: Optional custom base URL.
        """
        super().__init__(api_key)
        self.client = OAClient(api_key=api_key, base_url=base_url)
    
    def call(self, model: str, message: str) -> Tuple[str, int]:
        """
        Call OpenAI chat completion API.
        
        Args:
            model: Model name (e.g., "gpt-4").
            message: User message.
            
        Returns:
            Tuple of (response content, timestamp).
        """
        response = self.client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": message},
            ],
            stream=False
        )
        return response.choices[0].message.content, response.created
