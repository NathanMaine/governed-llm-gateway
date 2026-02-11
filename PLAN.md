# PLAN -- Governed LLM Gateway

## Objectives

### Slice 1 (complete)
- Single HTTP endpoint for chat/completions that routes by model alias.
- Central config for providers, model aliases, and rate-limit parameters.
- Simple per-client rate limiting (in-memory).
- Logging/telemetry for each request outcome and approximate usage.
- Clear errors for rate-limit or policy rejections.

### Slice 2 -- Compliance-first features (complete)
- Immutable hash-chain audit trail with tamper detection.
- Policy-as-code engine with YAML-defined rules.
- PII detection and blocking (SSN, credit card, email, phone).
- Data classification gating (PHI, PCI) and jurisdiction-based routing.
- Approval workflow support (REQUIRE_APPROVAL decision).
- Compliance evidence export mapped to SOC 2 and HIPAA controls.
- Merkle tree root computation for periodic verification.

## Approach
- Compliance is the primary design constraint, not an afterthought.
- Policy evaluation happens BEFORE provider dispatch (DENY = prompt never leaves infrastructure).
- Audit trail is append-only JSONL with cryptographic hash chain.
- Prompts and responses are SHA-256 hashed, never stored raw.
- Evidence packages are structured JSON, filterable by control ID and date range.

## Work slices
1) [x] **Scaffold**: `src/`, config loader, types, basic logging helper.
2) [x] **Routing + provider adapter**: resolve alias -> provider; call provider client stub.
3) [x] **Rate limiting**: per-client in-memory limiter; friendly error shape.
4) [x] **Telemetry/logging**: log request metadata, outcome, usage.
5) [x] **Examples**: sample config, sample curl, README run notes.
6) [x] **Audit trail**: hash-chain linked JSONL log, verify_chain(), Merkle root.
7) [x] **Policy engine**: YAML rules, PII detection, data classification, jurisdiction, keywords.
8) [x] **Compliance evidence**: SOC 2 + HIPAA control mappings, evidence package generation.
9) [x] **Integration**: audit + policy wired into request flow, response metadata.
10) [x] **Tests**: 103 tests covering all modules.
11) [x] **Documentation**: README, SPEC, compliance framework tables.

## Risks / constraints
- Rate-limit accuracy is coarse; document that it is approximate and in-memory only.
- Do not store secrets in config; rely on env vars.
- PII detection uses regex patterns; not a substitute for a dedicated DLP solution.
- Policy engine covers common patterns; full OPA/Rego deferred to future iteration.

## Acceptance
- [x] Starts with sample config and runs locally.
- [x] `/v1/chat` accepts requests, evaluates policy, routes, and returns response with audit metadata.
- [x] Policy engine blocks PII, gates PHI/PCI, supports jurisdiction routing.
- [x] Hash-chain audit trail with tamper detection.
- [x] Evidence packages generated for SOC 2 and HIPAA controls.
- [x] 103 tests passing.
