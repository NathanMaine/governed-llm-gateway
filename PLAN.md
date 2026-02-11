# PLAN — Governed LLM Gateway (Prototype)

## Objectives (slice 1)
- Single HTTP endpoint for chat/completions that routes by model alias.
- Central config for providers, model aliases, and rate-limit parameters.
- Simple per-client rate limiting (in-memory is fine).
- Logging/telemetry for each request outcome and approximate usage.
- Clear errors for rate-limit or policy rejections.

## Approach
- Keep the surface small: one endpoint (`/v1/chat`), JSON request/response.
- Configuration-driven routing: model alias -> provider/model mapping; env vars for secrets.
- Provider adapter pattern so new providers can be added without touching the handler.
- In-memory token/request limiter (per `client_id`), pluggable later.
- Logging to stdout plus a rolling log file for local review.

## Work slices
1) [x] **Scaffold**: `src/`, config loader, types, basic logging helper.
2) [x] **Routing + provider adapter**: resolve alias -> provider; call provider client stub.
3) [x] **Rate limiting**: per-client in-memory limiter; friendly error shape.
4) [x] **Telemetry/logging**: log request metadata, outcome, usage (approx if provider returns).
5) [x] **Examples**: sample config, sample curl, README run notes.

## Risks / constraints
- Over-broad config scope -- keep to one provider + one model alias initially.
- Rate-limit accuracy is coarse; document that it is approximate and in-memory only.
- Do not store secrets in config; rely on env vars.

## Acceptance for slice 1
- [x] Starts with sample config and runs locally.
- [x] `/v1/chat` accepts a request with `client_id`, `model`, `messages` and forwards to the configured provider.
- [x] Per-client in-memory rate limit enforced; returns a structured rate-limit error.
- [x] Logs each request with model alias, provider, client id, outcome, and usage when available.
