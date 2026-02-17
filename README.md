# Governed LLM Gateway

**The compliance-first LLM gateway.** Route LLM requests through a single governed endpoint with tamper-evident audit trails, policy-as-code enforcement, and compliance evidence export -- built for regulated industries.

---

## Why This Exists

The LLM gateway space has mature options for routing and load balancing. What none of them address is the question a CISO asks before approving LLM usage in a regulated environment:

> "How do we prove to auditors that every LLM interaction was authorized, logged immutably, and compliant with our policies?"

Governed LLM Gateway answers that question.

## Feature Comparison

| Capability | Governed LLM Gateway | LiteLLM | Portkey | TensorZero |
|---|---|---|---|---|
| Multi-provider routing | Yes | Yes | Yes | Yes |
| Rate limiting | Yes | Yes | Yes | Yes |
| **Tamper-evident audit trail** | **Yes (hash-chain)** | No | No | No |
| **Policy-as-code enforcement** | **Yes (YAML rules)** | No | No | No |
| **Compliance evidence export** | **Yes (SOC2/HIPAA)** | No | No | No |
| **PII detection in prompts** | **Yes (built-in)** | No | No | No |
| **Approval workflows** | **Yes** | No | No | No |
| Prompt/response never stored raw | **Yes (hashed only)** | No | No | No |

## Architecture

```
                    +------------------------------------------+
                    |         Governed LLM Gateway              |
                    |                                          |
  Client Request    |  1. Request Validation                   |
  ───────────────>  |  2. Policy Engine ──> ALLOW/DENY/APPROVE |
                    |  3. Route Resolution                     |
                    |  4. Rate Limiting                        |
                    |  5. Provider Dispatch ───> LLM Provider  |
                    |  6. Audit Trail (hash-chain append)      |
  <───────────────  |  7. Response + policy + audit metadata   |
  Response          |                                          |
                    +------------------------------------------+
                         |              |              |
                    +---------+   +-----------+  +----------+
                    | Audit   |   | Policy    |  | Evidence |
                    | Trail   |   | Rules     |  | Packages |
                    | (JSONL) |   | (YAML)    |  | (JSON)   |
                    +---------+   +-----------+  +----------+
```

### Key Compliance Properties

- **Immutable audit trail**: Every request produces a hash-chain linked entry. Each entry includes the SHA-256 hash of the previous entry, creating a tamper-evident chain of custody. If any historical entry is modified, `verify_chain()` detects it.
- **Content never stored raw**: Prompts and responses are SHA-256 hashed before logging. The audit trail proves *that* a request happened and *what policy decision* was made, without exposing sensitive content.
- **Policy-before-dispatch**: Policy rules are evaluated *before* the request reaches any LLM provider. A DENY decision means the prompt never leaves your infrastructure.
- **Merkle tree verification**: Periodic verification computes a Merkle root across all chain hashes for efficient integrity checking.

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the gateway

```bash
uvicorn src.app:app --reload
```

### 3. Send a request

```bash
curl -X POST http://127.0.0.1:8000/v1/chat \
  -H "Content-Type: application/json" \
  -H "X-API-Key: test-key-1" \
  -d '{
    "client_id": "dev-local-1",
    "model": "default-chat",
    "messages": [
      {"role": "user", "content": "Explain rate limiting in simple terms."}
    ],
    "data_classification": "public",
    "jurisdiction": "US"
  }'
```

The response includes policy evaluation and audit trail metadata:

```json
{
  "id": "gw-a1b2c3d4e5f6",
  "model": "default-chat",
  "provider": "openai",
  "usage": {"prompt_tokens": 7, "completion_tokens": 17, "total_tokens": 24},
  "message": {"role": "assistant", "content": "..."},
  "policy": {
    "decision": "ALLOW",
    "triggered_rules": [],
    "details": {}
  },
  "audit": {
    "chain_hash": "a3f8...64-char-hex-hash",
    "entry_index": 42
  }
}
```

### 4. See policy enforcement in action

Send a request containing PII -- the gateway blocks it before it reaches any provider:

```bash
curl -X POST http://127.0.0.1:8000/v1/chat \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "dev-local-1",
    "model": "default-chat",
    "messages": [
      {"role": "user", "content": "Look up patient SSN 123-45-6789"}
    ]
  }'
```

Response:

```json
{
  "error": {
    "type": "policy_denied",
    "message": "Request denied by policy: block-pii-in-prompts"
  },
  "policy": {
    "decision": "DENY",
    "triggered_rules": ["block-pii-in-prompts"],
    "details": {"block-pii-in-prompts": "Deny requests containing PII..."}
  }
}
```

## Authentication

API key authentication is enabled by default. Configure keys in `config/example.config.json`:

```json
"auth": {
  "enabled": true,
  "api_keys": {
    "dev-key-1": "1255558df586ae279007fffa27ec17451d1507f7ac5442add9ffbc070f9f623b"
  }
}
```

Keys are stored as SHA-256 hashes, never plaintext. Generate a hash for a new key:

```python
from src.auth import hash_api_key
print(hash_api_key("your-secret-key"))
```

Requests without a valid `X-API-Key` header receive a `401` response. Auth failures are recorded in the audit trail. Set `"enabled": false` to disable authentication.

## Policy Engine

Policies are defined in YAML and evaluated on every request before provider dispatch. See `config/policies/default.yaml` for the full example.

```yaml
rules:
  - name: block-pii-in-prompts
    description: Deny requests containing PII (SSN, credit cards, etc.)
    action: DENY
    conditions:
      pii_detected: true

  - name: require-approval-for-phi
    description: Require approval for Protected Health Information
    action: REQUIRE_APPROVAL
    conditions:
      data_classification:
        - PHI

  - name: eu-data-residency-routing
    description: Flag EU-jurisdiction requests for data residency review
    action: REQUIRE_APPROVAL
    conditions:
      jurisdiction:
        - EU
```

### Supported Rule Conditions

| Condition | Description |
|-----------|-------------|
| `pii_detected` | Scan prompt for SSN, credit card, email, phone patterns |
| `data_classification` | Match against PHI, PCI, or custom classification labels |
| `jurisdiction` | Match against EU, US, or custom jurisdiction codes |
| `blocked_models` | Deny access to specific model aliases |
| `blocked_clients` | Deny access to specific client IDs |
| `blocked_keywords` | Scan prompt for specific keywords or phrases |
| `max_prompt_length` | Flag prompts exceeding a character limit |

### Policy Decisions

| Decision | HTTP Status | Behavior |
|----------|-------------|----------|
| `ALLOW` | 200 | Request proceeds to provider |
| `DENY` | 403 | Request blocked, never reaches provider |
| `REQUIRE_APPROVAL` | 403 | Request blocked pending approval workflow |

### Production Considerations

The default policy file uses descriptive rule names like `block-pii-in-prompts` for readability. In production deployments, use opaque rule identifiers (e.g., `POL-001`, `R-4a2f`) to avoid leaking internal policy structure in error responses and audit logs.

## Compliance Framework Support

The gateway maps audit trail entries to specific compliance controls:

### SOC 2 Type II

| Control | Title | What the Gateway Provides |
|---------|-------|---------------------------|
| CC6.1 | Logical Access Controls | Per-client authentication, policy-gated access |
| CC6.6 | System Boundaries | Policy enforcement blocking unauthorized requests |
| CC6.8 | Malicious Software Controls | Keyword/content blocking in prompts |
| CC7.1 | Detection and Monitoring | Complete audit trail of all LLM interactions |
| CC7.2 | Monitoring System Components | Hash-chain verified request logging |
| CC8.1 | Change Management | Approval workflows for sensitive operations |

### HIPAA Security Rule

| Control | Title | What the Gateway Provides |
|---------|-------|---------------------------|
| 164.312(a)(1) | Access Control | Client-based access control with policy enforcement |
| 164.312(a)(2)(i) | Unique User Identification | Per-request client_id and request_id tracking |
| 164.312(b) | Audit Controls | Immutable, hash-chain linked audit trail |
| 164.312(c)(1) | Integrity | Tamper-evident chain with Merkle tree verification |
| 164.312(d) | Authentication | Client identification on every request |
| 164.312(e)(1) | Transmission Security | Content hashing (prompts/responses never stored raw) |

### Generating Evidence Packages

```python
from src.audit import AuditTrail
from src.compliance import generate_evidence_package, export_evidence_package

trail = AuditTrail("logs/audit.jsonl")
entries = trail.read_entries()

package = generate_evidence_package(
    entries=entries,
    control_id="164.312(b)",
    framework="HIPAA",
    date_start="2025-01-01T00:00:00Z",
    date_end="2025-03-31T23:59:59Z",
)

export_evidence_package(package, "evidence/hipaa-164.312b-q1-2025.json")
```

## Configuration

Configuration is loaded from a JSON file. See `config/example.config.json` for the full schema.

| Section | Description |
|---------|-------------|
| `providers` | Provider definitions with `base_url` and `api_key_env` (env var name) |
| `aliases` | Model alias to provider/model mappings |
| `rate_limit` | `requests_per_minute` and optional `tokens_per_minute` |
| `max_prompt_tokens` | Optional cap on prompt size (approximate word count) |
| `log_file` | Path to the telemetry log file |
| `policy_file` | Path to the YAML policy file |
| `audit_log_file` | Path to the immutable JSONL audit trail |
| `compliance` | Compliance settings: frameworks, evidence output, retention |

**API keys** are never stored in the config file. Set them as environment variables:

```bash
export OPENAI_API_KEY=sk-your-key-here
```

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
  audit.py        - Immutable hash-chain audit trail
  policy.py       - Policy-as-code engine (YAML rules)
  compliance.py   - Compliance evidence collector (SOC2/HIPAA)
config/
  example.config.json       - Sample configuration
  policies/default.yaml     - Default policy rules
tests/                      - 103 tests covering all modules
logs/                       - Append-only log output (gitignored)
evidence/                   - Compliance evidence packages (gitignored)
```

## Running Tests

```bash
python3 -m pytest tests/ -v
```

## Status

- [x] Multi-provider routing with model aliases
- [x] Per-client rate limiting (request and token)
- [x] Structured telemetry logging
- [x] **Immutable hash-chain audit trail**
- [x] **Policy-as-code engine (YAML rules)**
- [x] **PII detection and blocking**
- [x] **Data classification gating (PHI/PCI)**
- [x] **Jurisdiction-based routing rules**
- [x] **Approval workflows for sensitive operations**
- [x] **Compliance evidence export (SOC2/HIPAA)**
- [x] **Tamper detection with Merkle tree verification**

---

Built for teams that need to prove their LLM usage is governed, auditable, and compliant.
