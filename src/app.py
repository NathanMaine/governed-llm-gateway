"""FastAPI application for the governed LLM gateway.

Provides a single /v1/chat endpoint that validates requests, resolves model
aliases, enforces rate limits, forwards to the appropriate provider, and
logs telemetry.
"""

import os
import uuid
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from src.config import GatewayConfig, load_config
from src.limiter import RateLimitExceeded, RateLimiter
from src.models import (
    ChatRequest,
    ChatResponse,
    ErrorDetail,
    ErrorResponse,
    UsageInfo,
)
from src.provider import call_provider
from src.router import RoutingError, resolve_route
from src.telemetry import log_request, setup_logging

CONFIG_PATH = os.getenv("GATEWAY_CONFIG", "config/example.config.json")

_config: Optional[GatewayConfig] = None
_limiter: Optional[RateLimiter] = None


def get_config() -> GatewayConfig:
    """Return the loaded gateway configuration (lazy-init)."""
    global _config
    if _config is None:
        _config = load_config(CONFIG_PATH)
    return _config


def get_limiter() -> RateLimiter:
    """Return the rate limiter (lazy-init from config)."""
    global _limiter
    if _limiter is None:
        cfg = get_config()
        _limiter = RateLimiter(
            requests_per_minute=cfg.rate_limit.requests_per_minute,
            tokens_per_minute=cfg.rate_limit.tokens_per_minute,
        )
    return _limiter


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    """Initialize config and logging on application startup."""
    cfg = get_config()
    setup_logging(cfg.log_file)
    get_limiter()
    yield


app = FastAPI(title="Governed LLM Gateway", version="0.1.0", lifespan=lifespan)


def _error_response(status: int, error_type: str, message: str) -> JSONResponse:
    """Build a consistent JSON error response."""
    body = ErrorResponse(error=ErrorDetail(type=error_type, message=message))
    return JSONResponse(status_code=status, content=body.model_dump())


@app.post("/v1/chat", response_model=None)
async def chat(request: ChatRequest) -> JSONResponse:
    """Handle a chat completion request.

    Validates the request, resolves the model alias, enforces rate limits,
    calls the provider, and returns a structured response.
    """
    config = get_config()
    limiter = get_limiter()
    request_id = "gw-{}".format(uuid.uuid4().hex[:12])

    # --- Prompt size validation ---
    if config.max_prompt_tokens is not None:
        total_words = sum(len(m.content.split()) for m in request.messages)
        if total_words > config.max_prompt_tokens:
            log_request(
                client_id=request.client_id,
                alias=request.model,
                provider=None,
                outcome="validation_error",
                error="Prompt too large",
                request_id=request_id,
            )
            return _error_response(
                400,
                "validation_error",
                "Prompt size ({} approx tokens) exceeds maximum ({}).".format(
                    total_words, config.max_prompt_tokens
                ),
            )

    # --- Routing ---
    try:
        route = resolve_route(config, request.model)
    except RoutingError as exc:
        log_request(
            client_id=request.client_id,
            alias=request.model,
            provider=None,
            outcome="routing_error",
            error=str(exc),
            request_id=request_id,
        )
        return _error_response(400, "routing_error", str(exc))

    # --- Rate limiting ---
    try:
        limiter.check(request.client_id)
    except RateLimitExceeded as exc:
        log_request(
            client_id=request.client_id,
            alias=request.model,
            provider=route.provider.name,
            outcome="rate_limited",
            error=exc.detail,
            request_id=request_id,
        )
        return _error_response(429, "rate_limit_exceeded", exc.detail)

    # --- Provider call ---
    try:
        result = await call_provider(route.provider, route.model, request.messages)
    except httpx.HTTPStatusError as exc:
        log_request(
            client_id=request.client_id,
            alias=request.model,
            provider=route.provider.name,
            outcome="provider_error",
            error="Provider returned HTTP {}".format(exc.response.status_code),
            request_id=request_id,
        )
        return _error_response(
            502,
            "provider_error",
            "Provider returned HTTP {}.".format(exc.response.status_code),
        )
    except Exception as exc:
        log_request(
            client_id=request.client_id,
            alias=request.model,
            provider=route.provider.name,
            outcome="provider_error",
            error=str(exc),
            request_id=request_id,
        )
        return _error_response(
            502,
            "provider_error",
            "Failed to reach provider: {}".format(exc),
        )

    # --- Record token usage for rate limiting ---
    try:
        limiter.record_tokens(request.client_id, result.usage.total_tokens)
    except RateLimitExceeded:
        pass  # Already served this request; log but do not reject

    # --- Telemetry ---
    log_request(
        client_id=request.client_id,
        alias=request.model,
        provider=route.provider.name,
        outcome="success",
        usage=result.usage.model_dump(),
        request_id=request_id,
    )

    response = ChatResponse(
        id=request_id,
        model=request.model,
        provider=route.provider.name,
        usage=result.usage,
        message=result.message,
    )
    return JSONResponse(status_code=200, content=response.model_dump())


@app.exception_handler(422)
async def validation_exception_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    """Convert FastAPI's validation errors into our error envelope format."""
    return _error_response(
        422,
        "validation_error",
        "Request validation failed: {}".format(exc),
    )
