"""Request and response models for the governed LLM gateway."""

from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    """A single message in a chat conversation."""

    role: str
    content: str


class ChatRequest(BaseModel):
    """Incoming chat request from the client."""

    client_id: str = Field(..., min_length=1, description="Caller identifier")
    model: str = Field(..., min_length=1, description="Model alias to route to")
    messages: List[ChatMessage] = Field(
        ..., min_length=1, description="Conversation messages"
    )
    metadata: Optional[Dict] = Field(
        default=None, description="Optional caller metadata"
    )


class UsageInfo(BaseModel):
    """Token usage information returned by the provider."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0


class ChatResponse(BaseModel):
    """Successful chat response envelope."""

    id: str
    model: str
    provider: str
    usage: UsageInfo
    message: ChatMessage


class ErrorDetail(BaseModel):
    """Structured error detail."""

    type: str
    message: str


class ErrorResponse(BaseModel):
    """Error response envelope."""

    error: ErrorDetail
