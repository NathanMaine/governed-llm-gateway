# TASKS -- Governed LLM Gateway

## Slice 1 -- Core Gateway

- [x] Scaffold folders: create `src/`, `config/`, `logs/` (gitkeep for empty dirs if needed).
- [x] Config loader: read model alias map, provider configs, rate-limit params; support env vars for secrets.
- [x] Provider adapter: implement a simple OpenAI-style client (env key, base URL, model); return usage if provided.
- [x] Request validation: ensure `client_id`, `model`, and chat `messages` are present; clamp prompt size if configured.
- [x] Routing: resolve alias to provider/model; handle unknown alias error.
- [x] In-memory rate limiter: per `client_id` (req/min and optional tokens/min approximation); return structured error.
- [x] Logging/telemetry: stdout + append-only log file with timestamp, client id, alias, provider, outcome, usage.
- [x] Error envelopes: consistent JSON for validation, rate-limit, and provider errors.
- [x] Examples: sample `config/example.config.json` and sample `curl` request in README.
- [x] Smoke tests: minimal test or script to hit `/v1/chat` happy path and rate-limit rejection.
- [x] README updates: add run instructions and configuration notes.

## Slice 2 -- Compliance-First Features

- [x] Immutable audit trail (`src/audit.py`): hash-chain linked JSONL entries, SHA-256 chain hashes, append-only storage.
- [x] Chain verification: `verify_chain()` to detect tampering of any historical entry.
- [x] Merkle tree: `compute_merkle_root()` for periodic integrity verification.
- [x] Content hashing: `hash_content()` for prompts and responses (never store raw).
- [x] Chain resumption: new AuditTrail instance continues chain from existing file.
- [x] Policy engine (`src/policy.py`): YAML-based rule definitions with ALLOW/DENY/REQUIRE_APPROVAL.
- [x] PII detection: regex patterns for SSN, credit card, email, phone number.
- [x] Data classification gating: PHI and PCI require approval.
- [x] Jurisdiction routing: EU data residency flagging.
- [x] Keyword blocking: configurable blocked keywords list.
- [x] Model and client access control: blocked_models and blocked_clients lists.
- [x] Prompt length limits: max_prompt_length condition.
- [x] Sample policies: `config/policies/default.yaml` with production-ready rules.
- [x] Compliance evidence collector (`src/compliance.py`): SOC 2 and HIPAA control mappings.
- [x] Evidence package generation: `generate_evidence_package()` with date range filtering.
- [x] Evidence export: `export_evidence_package()` writes JSON to file.
- [x] Integration: audit trail and policy engine wired into `src/app.py` request flow.
- [x] Updated models: `PolicyInfo` and `AuditInfo` in response envelopes.
- [x] Updated config: `policy_file`, `audit_log_file`, and `compliance` sections.
- [x] Tests: 103 tests across audit, policy, compliance, app, config, limiter, router.
- [x] README: compliance-first positioning, feature comparison, architecture diagram.
- [x] SPEC: updated to reflect compliance-first design.
