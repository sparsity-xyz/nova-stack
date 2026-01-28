"""AI Models package for the chat-bot service."""

from .platform import Platform
from .open_ai import OpenAI

__all__ = ['Platform', 'OpenAI']
