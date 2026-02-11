"""Smoke tests for the /v1/chat endpoint."""

import json
import os
from pathlib import Path
from typing import Dict

import pytest
from httpx import ASGITransport, AsyncClient

from src import app as app_module
from src.app import app


@pytest.fixture(autouse=True)
def _reset_app_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset the app's global state before each test and point to a test config."""
    # Build a test config
    config = {
        "providers": {
            "test-provider": {
                "base_url": "https://api.example.com/v1",
                "api_key_env": "TEST_API_KEY",
                "default_model": "test-model",
            }
        },
        "aliases": {
            "default-chat": {
                "provider": "test-provider",
                "model": "test-model",
            }
        },
        "rate_limit": {
            "requests_per_minute": 3,
            "tokens_per_minute": 10000,
        },
        "max_prompt_tokens": 500,
        "log_file": str(tmp_path / "test.log"),
    }
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(config))

    # Clear API key so stub mode is used
    monkeypatch.delenv("TEST_API_KEY", raising=False)

    # Point the app to our test config and reset cached state
    monkeypatch.setattr(app_module, "CONFIG_PATH", str(config_path))
    monkeypatch.setattr(app_module, "_config", None)
    monkeypatch.setattr(app_module, "_limiter", None)


def _make_request_body(
    client_id: str = "test-client",
    model: str = "default-chat",
    content: str = "Hello",
) -> Dict:
    return {
        "client_id": client_id,
        "model": model,
        "messages": [{"role": "user", "content": content}],
    }


@pytest.mark.asyncio
async def test_happy_path_stub_mode() -> None:
    """A valid request with no API key returns a stub response."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/v1/chat", json=_make_request_body())

    assert resp.status_code == 200
    data = resp.json()
    assert data["id"].startswith("gw-")
    assert data["model"] == "default-chat"
    assert data["provider"] == "test-provider"
    assert data["message"]["role"] == "assistant"
    assert "stub response" in data["message"]["content"].lower()
    assert data["usage"]["total_tokens"] > 0


@pytest.mark.asyncio
async def test_unknown_alias() -> None:
    """Requesting an unknown model alias returns a routing error."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat", json=_make_request_body(model="nonexistent")
        )

    assert resp.status_code == 400
    data = resp.json()
    assert data["error"]["type"] == "routing_error"


@pytest.mark.asyncio
async def test_rate_limit_exceeded() -> None:
    """Exceeding the rate limit returns a 429 with a structured error."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # The test config allows 3 req/min
        for _ in range(3):
            resp = await client.post("/v1/chat", json=_make_request_body())
            assert resp.status_code == 200

        # The 4th request should be rejected
        resp = await client.post("/v1/chat", json=_make_request_body())

    assert resp.status_code == 429
    data = resp.json()
    assert data["error"]["type"] == "rate_limit_exceeded"


@pytest.mark.asyncio
async def test_missing_client_id() -> None:
    """Omitting client_id returns a validation error."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat",
            json={
                "model": "default-chat",
                "messages": [{"role": "user", "content": "hi"}],
            },
        )

    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_missing_messages() -> None:
    """Omitting messages returns a validation error."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat",
            json={"client_id": "test", "model": "default-chat"},
        )

    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_prompt_too_large() -> None:
    """A prompt exceeding max_prompt_tokens returns a validation error."""
    long_content = " ".join(["word"] * 600)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat", json=_make_request_body(content=long_content)
        )

    assert resp.status_code == 400
    data = resp.json()
    assert data["error"]["type"] == "validation_error"
    assert "exceeds maximum" in data["error"]["message"].lower()


@pytest.mark.asyncio
async def test_separate_clients_independent_limits() -> None:
    """Different client_ids have independent rate limit windows."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        for i in range(3):
            resp = await client.post(
                "/v1/chat", json=_make_request_body(client_id="client-a")
            )
            assert resp.status_code == 200

        # client-b should still have full quota
        resp = await client.post(
            "/v1/chat", json=_make_request_body(client_id="client-b")
        )
        assert resp.status_code == 200
