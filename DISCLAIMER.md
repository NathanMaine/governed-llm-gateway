# Disclaimer

This repository represents personal research and experimentation by Nathan Maine.
It is not affiliated with, endorsed by, or representative of any current or past employer.

## Key Points

- This project is a prototype and proof of concept, not a production-ready system.
- The code, specifications, and documentation are provided as-is, with no warranty of any kind.
- Nothing in this repository should be interpreted as legal, compliance, or security advice.
- Any similarities to internal systems, processes, or tools of any employer are coincidental or reflect common industry practices.

## By Viewing or Using This Material, You Agree That

- You are responsible for independently evaluating any approach before using it in a real system.
- You will not treat this repository as official guidance or endorsed work of any organization.

## If You Are an Employer or Reviewer

Please treat this project as a demonstration of personal thinking, design, and implementation skill, created on personal time and equipment, with a focus on generic patterns rather than proprietary details.

---

## Patent Notice and Technical Boundary Statement

**Date:** February 11, 2026

### Related Patent Application

Memoriant, Inc. has filed a U.S. provisional patent application titled *"Distributed Token-Accounting Gateway with Predictive Admission, Sharded Reservations, Split-Trust Co-Signing, and Deterministic Refund Reconciliation"* (Attorney Docket: MEM-ADAPTIVE-PPA-20251110, filed November 18, 2025). The patent application describes a distributed, serverless-friendly gateway architecture for governing large-language-model (LLM) calls using specific mechanisms enumerated below.

**This repository does not implement, embody, or practice any of the claims described in that patent application.** The two systems address different problems using fundamentally different architectures. This notice defines the precise technical boundary between the patented invention and this open-source repository.

---

### What This Repository IS

This repository is a **compliance-focused LLM gateway** — a single-process FastAPI application that enforces policy rules before dispatching LLM requests and maintains an immutable local audit trail. Specifically, this repository implements:

1. **Policy-as-code enforcement** using YAML-defined rules evaluated in order, with seven condition types (PII regex detection for SSN, credit card, email, and phone patterns; data classification matching; jurisdiction matching; blocked model lists; blocked client lists; keyword blocking; and prompt length limits). Rules are combined using AND logic within a rule, and the most restrictive outcome wins across rules (DENY > REQUIRE_APPROVAL > ALLOW).

2. **SHA-256 hash-chain audit trail** stored as local JSONL, where each entry includes the SHA-256 hash of the previous entry to form a tamper-evident chain. Chain integrity is verified by recomputing every hash sequentially.

3. **Merkle tree verification** computing a root hash from bottom-up SHA-256 pair combination across all chain entries for efficient integrity checking.

4. **Content hashing without storage** — prompts and responses are SHA-256 hashed before audit logging; raw text is never persisted in the audit trail.

5. **Per-client fixed-window rate limiting** using in-memory counters tracking request count and token count per client within fixed time windows.

6. **Compliance evidence export** mapping audit trail entries to twelve specific regulatory controls across SOC 2 Type II (CC6.1, CC6.6, CC6.8, CC7.1, CC7.2, CC8.1) and HIPAA Security Rule (164.312(a)(1), 164.312(a)(2)(i), 164.312(b), 164.312(c)(1), 164.312(d), 164.312(e)(1)), with date-filtered evidence packages including chain verification status and summary statistics.

7. **Model alias routing** resolving model aliases to provider/model pairs via static configuration.

8. **Stub-mode operation** returning deterministic mock responses when no provider API key is configured.

---

### What This Repository IS NOT

This repository **does not implement any of the following mechanisms**, each of which corresponds to one or more claims in the referenced patent application:

**Sharded Transactional Token Reservations (Patent Claims 1, 2, 6, 14, 15).**
This repository does not partition token budgets into shards. There is no shard function (sid = H(actorId) mod N). There are no transactional hold objects. There is no idempotent reservation system. There is no distributed datastore for token state. Rate limiting is performed using simple in-memory per-client counters in a single process — not via sharded ledgers with atomic transactions.

**Predictive Admission (Patent Claims 1, 11, 16).**
This repository does not predict token usage or latency. There is no forecasted token count (T̂). There is no predicted p95 latency (L̂_p). There is no EWMA (Exponentially Weighted Moving Average) model. Admission decisions are based on static policy rule evaluation (regex pattern matching, classification matching, jurisdiction matching) — not on predictive models comparing forecasts to quotas or latency SLOs.

**Provider Scoring and Routing (Patent Claims 1, 4, 10).**
This repository does not score providers. There is no composite scoring formula (σ_k = w_s·S_k − w_c·P_k − w_l·L_p,k). There is no weighted evaluation of success rate, effective price, or latency. There is no dynamic provider ranking. Provider selection is performed via static model alias configuration — not via scored, dynamic routing.

**Bounded Retry with Backoff (Patent Claims 1, 5).**
This repository does not implement bounded retry logic. There is no retry-at-most-once policy. There is no exponential backoff. Failed provider calls return errors directly to the client.

**Deterministic Reconciliation and Refund Ledger (Patent Claims 1, 6).**
This repository does not reconcile actual token usage against reserved amounts. There is no refund ledger. There is no idempotency key for refund deduplication. There are no actualization or refund entries. Token counts are recorded for telemetry purposes only — they do not participate in a transactional reservation/refund lifecycle.

**Hierarchical Quotas (Patent Claim 8).**
This repository does not implement hierarchical budgets. There is no tenant → project → user → agent quota hierarchy. Rate limits are flat, per-client values defined in a single configuration file.

**Multi-Queue Fairness with Aging (Patent Claims 1, 9).**
This repository does not implement multiple request queues. There are no traffic classes (e.g., interactive vs. batch). There are no capacity slices, virtual finish times, or aging mechanisms. There is no starvation prevention logic. All requests are processed through a single request path.

**TTL-Based Dynamic Configuration Refresh (Patent Claim 3).**
This repository does not implement TTL-based configuration caching or refresh. Configuration is loaded at application startup and remains static for the lifetime of the process.

**Split-Trust Co-Signing (Patent Claim 17).**
This repository does not implement a split-trust architecture. There is no separate guard component. There is no co-signing of requests or responses. There are no DSSE (Dead Simple Signing Envelope) envelopes. There is no transparency log submission. There is no HSM/KMS key signing. There is no digest-binding between two gateway components.

**Decision Log Provenance Hashing (Patent Claim 7).**
This repository does not compute provenance hashes over decision log entries that include policy snapshot hashes, admission outcomes, provider scores, failover rationale, ledger references, or refund status. The audit trail records request metadata and policy decisions but does not implement the specific provenance hash structure described in the patent claims.

**Latency SLO Enforcement (Patent Claims 11, 12).**
This repository does not enforce latency SLOs. There is no p95 rolling window latency computation. There is no admission denial based on predicted latency exceeding a per-class target.

---

### Summary of Technical Differentiation

| Dimension | This Repository | Patent Application |
|---|---|---|
| **Architecture** | Single-process FastAPI application | Distributed, stateless serverless gateway with external datastore |
| **Token accounting** | In-memory per-client counters | Sharded transactional token buckets with idempotent holds |
| **Admission logic** | Static policy rule evaluation (regex, classification, jurisdiction) | Predictive admission using forecasted tokens and latency vs. quotas and SLOs |
| **Provider selection** | Static model alias mapping | Dynamic composite scoring (success rate, price, latency) with failover |
| **Failure handling** | Direct error return | Bounded retry with exponential backoff, deterministic refund reconciliation |
| **Quota model** | Flat per-client rate limits | Hierarchical tenant → project → user → agent budgets |
| **Request scheduling** | Single FIFO path | Multi-queue fairness governor with capacity slices and aging |
| **Configuration** | Static load at startup | TTL-based dynamic refresh from external config store |
| **Trust model** | Single gateway process | Split-trust with co-signing guard, DSSE envelopes, transparency log |
| **Audit mechanism** | SHA-256 hash-chain with Merkle tree (local JSONL) | Decision log with provenance hashing, policy snapshot hashes, ledger references |

---

### License and Patent Scope

This repository is licensed under the MIT License. The patent application referenced above covers a separate and distinct system architecture. Use of this open-source repository does not grant any license under the referenced patent application, nor does it require one.

---

*This notice is provided for informational purposes to establish the technical boundary between this open-source repository and the referenced patent application. It is not legal advice. For questions regarding the patent application, contact ip@memoriant.ai.*
