"""
Base Platform class for AI model integrations.
"""

import abc
from typing import List, Tuple


# Supported models for each platform
PLATFORM_MODELS = {
    "openai": ["gpt-5.1", "gpt-5", "gpt-5-mini", "gpt-4.1", "gpt-4.1-mini", "gpt-4o", "gpt-4o-mini", "gpt-4"]
}


class Platform(abc.ABC):
    """Abstract base class for AI platform integrations."""
    
    name: str
    support_models: List[str]
    
    def __init__(self, api_key: str):
        """
        Initialize the platform with an API key.
        
        Args:
            api_key: The API key for the platform.
        """
        self.api_key = api_key
        self.support_models = PLATFORM_MODELS.get(self.name, [])
    
    def check_support_model(self, model: str) -> bool:
        """
        Check if the model is supported by this platform.
        
        Args:
            model: The model name to check.
            
        Returns:
            True if the model is supported, False otherwise.
        """
        return model in self.support_models
    
    @abc.abstractmethod
    def call(self, model: str, message: str) -> Tuple[str, int]:
        """
        Call the AI model with a message.
        
        Args:
            model: The model name to use.
            message: The user message to send.
            
        Returns:
            A tuple of (response_content, timestamp).
        """
        raise NotImplementedError
