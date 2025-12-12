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

- [ ] Initial specification (`SPEC.md`)
- [ ] Minimal working gateway endpoint
- [ ] Basic rate limiting / per-key quotas
- [ ] Basic logging / telemetry
- [ ] Simple configuration file for models/providers

## How this repo is structured

- `SPEC.md` — detailed specification for this prototype
- `DISCLAIMER.md` — IP and usage disclaimer
- `memory/constitution.md` — constraints and instructions for IDE agents
- `specify/` and `.github/prompts/` — Spec Kit scaffolding
- `src/` — implementation (to be added as the project progresses)

---
