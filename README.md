# Governed LLM Gateway (Prototype)

This repository contains a small, personal proof-of-concept for a **governed LLM gateway**.

The idea is to put a lightweight service in front of one or more language model providers that can:

- Enforce **rate limits** and basic quotas
- Apply simple **routing rules** (e.g., by use case, cost, or model family)
- Attach basic **policy hooks** (e.g., deny certain routes, log specific calls)
- Emit **telemetry** for cost and usage visibility

This is a personal R&D project and a prototype, not a production system.

## Goals

- Explore how a gateway can centralize:
  - API keys and provider configuration
  - Routing, safety checks, and timeouts
  - Cost/usage logging
- Provide a small, concrete starting point that could later be extended.

## Non-goals

- This is **not** a full-featured API gateway
- No complex auth or fine-grained RBAC in the initial slice
- No guarantees about uptime, performance, or security

## Status

- [x] Initial specification (`SPEC.md`)
- [x] Minimal working gateway endpoint
- [x] Basic rate limiting / per-key quotas
- [x] Basic logging / telemetry
- [x] Simple configuration file for models/providers

## Project Structure

```
src/
  app.py          - FastAPI app with /v1/chat endpoint
  config.py       - Configuration loader
  models.py       - Request/response Pydantic models
  provider.py     - Provider adapter (OpenAI-compatible, with stub mode)
  router.py       - Model alias -> provider routing
  limiter.py      - In-memory per-client rate limiter
  telemetry.py    - Structured logging to stdout + log file
config/
  example.config.json - Sample configuration
tests/            - Pytest test suite
logs/             - Append-only log output (gitignored content)
```

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the gateway

```bash
# Uses config/example.config.json by default
uvicorn src.app:app --reload

# Or specify a custom config path
GATEWAY_CONFIG=config/example.config.json uvicorn src.app:app --reload
```

The gateway starts on `http://127.0.0.1:8000` by default.

### 3. Send a request

Without a real API key configured, the gateway runs in **stub mode** and returns
a canned response. This is useful for testing the routing, rate limiting, and
telemetry pipeline.

```bash
curl -X POST http://127.0.0.1:8000/v1/chat \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "dev-local-1",
    "model": "default-chat",
    "messages": [
      {"role": "user", "content": "Explain rate limiting in simple terms."}
    ]
  }'
```

**Example response (stub mode):**

```json
{
  "id": "gw-a1b2c3d4e5f6",
  "model": "default-chat",
  "provider": "openai",
  "usage": {
    "prompt_tokens": 7,
    "completion_tokens": 17,
    "total_tokens": 24
  },
  "message": {
    "role": "assistant",
    "content": "This is a stub response from the gateway. Configure a valid API key to get real completions."
  }
}
```

### 4. Test rate limiting

Send more requests than the configured limit to see the rate-limit error:

```bash
# With the example config (20 req/min), send 21 rapid requests:
for i in $(seq 1 21); do
  curl -s -X POST http://127.0.0.1:8000/v1/chat \
    -H "Content-Type: application/json" \
    -d '{"client_id":"test","model":"default-chat","messages":[{"role":"user","content":"hi"}]}' \
    | python3 -m json.tool
done
```

The 21st request returns:

```json
{
  "error": {
    "type": "rate_limit_exceeded",
    "message": "Request rate exceeded for client_id test (20 req/min)."
  }
}
```

## Configuration

Configuration is loaded from a JSON file. See `config/example.config.json` for the full schema.

Key sections:

| Section | Description |
|---------|-------------|
| `providers` | Provider definitions with `base_url` and `api_key_env` (env var name) |
| `aliases` | Model alias -> provider/model mappings |
| `rate_limit` | `requests_per_minute` and optional `tokens_per_minute` |
| `max_prompt_tokens` | Optional cap on prompt size (approximate word count) |
| `log_file` | Path to the append-only telemetry log file |

**API keys** are never stored in the config file. Set them as environment variables:

```bash
export OPENAI_API_KEY=sk-your-key-here
```

If no key is set for a provider, the gateway automatically uses stub mode for that provider.

## Running Tests

```bash
python3 -m pytest tests/ -v
```

## How this repo is structured

- `SPEC.md` -- detailed specification for this prototype
- `PLAN.md` -- implementation plan and work slices
- `TASKS.md` -- task checklist
- `DISCLAIMER.md` -- IP and usage disclaimer
- `memory/constitution.md` -- constraints and instructions for IDE agents
- `.specify/` and `.github/prompts/` -- Spec Kit scaffolding
- `src/` -- implementation
- `tests/` -- test suite
- `config/` -- configuration files

---
