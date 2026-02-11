# Specification: Governed LLM Gateway

## 1. Problem

Organizations adopting LLMs in regulated industries face a fundamental governance gap. Existing LLM gateways solve routing and cost optimization but do not answer the questions that compliance teams, CISOs, and auditors ask:

- How do we prove every LLM interaction was authorized by policy?
- How do we produce tamper-evident audit trails for regulators?
- How do we prevent sensitive data (PII, PHI) from reaching external providers?
- How do we map our LLM usage controls to specific compliance frameworks?

This gateway addresses that gap by making compliance the primary design constraint, not an afterthought.

## 2. Users and Use Cases

### Users

- **Compliance officers** who need evidence that LLM usage follows organizational policies.
- **Security teams** who need to enforce data classification and access controls on LLM requests.
- **Development teams** in regulated industries (healthcare, finance, government) who need a governed endpoint for LLM calls.
- **Auditors** who need structured evidence packages mapped to compliance controls.

### Primary Use Cases

1. **Policy-gated LLM access**
   - Every request is evaluated against YAML-defined policy rules before reaching any provider.
   - Decisions: ALLOW, DENY, or REQUIRE_APPROVAL.
   - PII detection blocks sensitive data from leaving the infrastructure.

2. **Immutable audit trail**
   - Every request (allowed or denied) produces a hash-chain linked audit entry.
   - SHA-256 chain: each entry includes the hash of the previous entry.
   - Tamper detection: `verify_chain()` detects any modification to historical entries.
   - Prompts and responses are hashed, never stored raw.

3. **Compliance evidence export**
   - Audit entries are mapped to SOC 2 and HIPAA control IDs.
   - `generate_evidence_package()` produces structured JSON evidence for auditors.
   - Date-range filtering, chain verification, and summary statistics included.

4. **Multi-provider routing with rate limiting**
   - Model alias to provider/model mapping via configuration.
   - Per-client rate limiting (requests/minute, tokens/minute).
   - Structured error responses for all rejection types.

## 3. Scope

### In scope

- Single HTTP endpoint (`/v1/chat`) with policy evaluation, routing, and audit.
- YAML-based policy engine with PII detection, data classification gating, jurisdiction rules, keyword blocking, and model/client access control.
- Hash-chain linked JSONL audit trail with Merkle tree verification.
- Compliance evidence collector supporting SOC 2 (CC6.1, CC6.6, CC6.8, CC7.1, CC7.2, CC8.1) and HIPAA (164.312 series).
- Multi-provider routing with OpenAI-compatible adapter and stub mode.
- Per-client in-memory rate limiting.
- Configuration via JSON with environment-variable-based secret management.

### Out of scope (future iterations)

- Full OPA/Rego integration (current YAML engine covers the core patterns).
- Persistent/distributed rate limiting.
- Multi-tenant billing and RBAC.
- Real-time approval workflow UI (current implementation returns REQUIRE_APPROVAL status for external workflow integration).
- Streaming responses.
- ISO 27001 control mappings (framework is extensible).

## 4. Constraints

- Implemented as a Python HTTP service using FastAPI.
- Runs locally with minimal setup (`pip install` and `uvicorn`).
- No employer-specific code, data, or confidential details.
- API keys resolved from environment variables, never stored in configuration.
- Audit trail is append-only; no mechanism to delete or overwrite entries.
- Prompts and responses are never stored in raw form (SHA-256 hashed only).

## 5. Interface

### Request

```json
POST /v1/chat
{
  "client_id": "dev-local-1",
  "model": "default-chat",
  "messages": [
    {"role": "user", "content": "Explain rate limiting."}
  ],
  "data_classification": "public",
  "jurisdiction": "US",
  "metadata": {"request_id": "optional-caller-id"}
}
```

### Successful Response

```json
{
  "id": "gw-req-123",
  "model": "default-chat",
  "provider": "openai",
  "usage": {
    "prompt_tokens": 42,
    "completion_tokens": 38,
    "total_tokens": 80
  },
  "message": {
    "role": "assistant",
    "content": "Rate limiting is..."
  },
  "policy": {
    "decision": "ALLOW",
    "triggered_rules": [],
    "details": {}
  },
  "audit": {
    "chain_hash": "a3f8...",
    "entry_index": 42
  }
}
```

### Policy Denial Response

```json
{
  "error": {
    "type": "policy_denied",
    "message": "Request denied by policy: block-pii-in-prompts"
  },
  "policy": {
    "decision": "DENY",
    "triggered_rules": ["block-pii-in-prompts"],
    "details": {}
  }
}
```

### Rate Limit Response

```json
{
  "error": {
    "type": "rate_limit_exceeded",
    "message": "Request rate exceeded for client_id dev-local-1 (20 req/min)."
  }
}
```

## 6. Configuration

JSON configuration file with sections for:

- **providers**: Provider definitions (base URLs, env var names for API keys)
- **aliases**: Model alias to provider/model mappings
- **rate_limit**: Per-client request and token limits
- **policy_file**: Path to YAML policy rules
- **audit_log_file**: Path to append-only JSONL audit trail
- **compliance**: Framework list, evidence output directory, retention days

## 7. Acceptance Criteria

- [x] `/v1/chat` accepts requests and routes to configured providers.
- [x] Policy engine evaluates YAML rules and returns ALLOW/DENY/REQUIRE_APPROVAL.
- [x] PII patterns (SSN, credit card, email, phone) detected and blocked.
- [x] Every request produces a hash-chain linked audit entry.
- [x] `verify_chain()` detects tampering of any historical entry.
- [x] Compliance evidence packages generated for SOC 2 and HIPAA controls.
- [x] Per-client rate limiting enforced with structured error responses.
- [x] Prompts and responses hashed (SHA-256), never stored raw.
- [x] 103 tests passing covering all modules.
