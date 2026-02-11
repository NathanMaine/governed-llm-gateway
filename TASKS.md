# TASKS — Governed LLM Gateway (Prototype)

- [x] Scaffold folders: create `src/`, `config/`, `logs/` (gitkeep for empty dirs if needed).
- [x] Config loader: read model alias map, provider configs, rate-limit params; support env vars for secrets.
- [x] Provider adapter: implement a simple OpenAI-style client (env key, base URL, model); return usage if provided.
- [x] Request validation: ensure `client_id`, `model`, and chat `messages` are present; clamp prompt size if configured.
- [x] Routing: resolve alias → provider/model; handle unknown alias error.
- [x] In-memory rate limiter: per `client_id` (req/min and optional tokens/min approximation); return structured error.
- [x] Logging/telemetry: stdout + append-only log file with timestamp, client id, alias, provider, outcome, usage.
- [x] Error envelopes: consistent JSON for validation, rate-limit, and provider errors.
- [x] Examples: sample `config/example.config.json` and sample `curl` request in README.
- [x] Smoke tests: minimal test or script to hit `/v1/chat` happy path and rate-limit rejection.
- [x] README updates: add run instructions and configuration notes.
