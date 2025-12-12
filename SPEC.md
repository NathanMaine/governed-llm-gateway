# Specification: Governed LLM Gateway (Prototype)

## 1. Problem

Teams experimenting with LLMs often call providers directly from many places:
local scripts, services, notebooks, and one-off tools. This fragments:

- API key management
- Rate limiting and cost visibility
- Safety and policy checks
- Observability of AI usage

This prototype explores a **simple central gateway** that sits in front of one or more LLM providers and implements:

- Basic routing
- Basic rate limiting
- Basic logging/telemetry
- Simple policy hooks

## 2. Users and Use Cases

### Users

- **Individual developers** who want a single endpoint for all LLM calls.
- **Experimenters** who want basic cost/usage visibility without re-architecting everything.

### Primary use cases (for the prototype)

1. **Single unified endpoint for completions/chat**
   - Caller sends: model alias, prompt, and optional metadata.
   - Gateway forwards to the appropriate provider/model.
   - Gateway returns the provider’s response (or a simplified envelope).

2. **Basic rate limiting**
   - Per API key or per “client id”
   - Simple limits: requests per minute, tokens per minute (approximate is okay at first).

3. **Basic logging**
   - Append logs to a file or simple data store:
     - timestamp
     - client id / API key id
     - model alias and provider
     - success/failure
     - approximate token usage (if available)

4. **Simple policy checks**
   - Configurable rules such as:
     - disable certain model aliases
     - require a client id
     - optionally block oversized prompts

## 3. Scope

In scope for the first slice:

- One HTTP endpoint (e.g., `/v1/chat` or `/v1/complete`).
- One or two LLM providers (e.g., OpenAI-style and one other),
  represented via configuration.
- A small configuration file for:
  - provider API keys (dummy or env-based)
  - model aliases → provider/model mapping
  - rate-limit parameters
- Very simple in-memory or file-based rate limiting (acceptable for a prototype).
- Logging to stdout and a basic log sink (file or simple DB).

Out of scope for the first slice:

- Full authentication/authorization
- Multi-tenant billing
- Complex policy engines
- Production-grade rate limiting and distributed quotas

## 4. Constraints

- Implemented as a small HTTP service (e.g., Node/TypeScript or Python).
- Run locally with minimal setup (`npm install` / `uv` / etc.).
- No employer-specific code, data, or confidential details.
- Keep provider-specific integrations generic and minimal.

## 5. Interface (First Slice)

### Request (example)

```jsonc
POST /v1/chat
{
  "client_id": "dev-local-1",
  "model": "default-chat",
  "messages": [
    { "role": "user", "content": "Explain rate limiting in simple terms." }
  ],
  "metadata": {
    "request_id": "optional-caller-id"
  }
}

Response (example)
{
  "id": "gw-req-123",
  "model": "default-chat",
  "provider": "example-llm-provider",
  "usage": {
    "prompt_tokens": 42,
    "completion_tokens": 38,
    "total_tokens": 80
  },
  "message": {
    "role": "assistant",
    "content": "Rate limiting is..."
  }
}


If the request is rejected due to rate limit or policy:

{
  "error": {
    "type": "rate_limit_exceeded",
    "message": "Request rate exceeded for client_id dev-local-1"
  }
}
```

6. Configuration

Example config.json (or .yaml):

Provider definitions (base URLs, env var names for keys)

Model aliases

Rate-limit parameters

7. Minimal Acceptable First Slice

For this prototype to be considered “working”:

 Accepts a POST request on a single endpoint.

 Forwards to one configured provider using a model alias.

 Logs each request/response outcome.

 Enforces a very simple per-client rate limit.

 Returns a clear error when the rate limit is exceeded.

Future iterations can add:

Additional providers

More sophisticated policies

Persistent storage for rate-limiting and logs

Better observability and dashboards.
