Constitution for IDE / AI Assistants (Governed LLM Gateway)

This document describes how IDE-integrated AI assistants (e.g., Copilot Chat) should behave when working in this repository.

1. General Rules

Treat this repository as a personal prototype, not a production system.

Avoid generating or suggesting:

Employer-specific code, secrets, or internal patterns

Proprietary details or references to private systems

Prefer clear, readable, maintainable code over micro-optimizations.

2. Scope of Assistance

AI assistants may help with:

Implementing the gateway HTTP endpoint(s)

Wiring simple provider clients

Implementing basic rate limiting and logging

Writing small tests or diagnostics

Updating documentation to match the code

AI assistants should not:

Introduce external dependencies that are clearly unnecessary

Embed API keys or secrets in code

Describe or replicate any non-public internal architecture from an employer

3. Design Preferences

Small, composable modules

Clear configuration boundaries (config.* files)

Straightforward error handling with helpful messages

Simple interfaces that can be extended later

4. Safety & IP

Do not mention any company names or brands in code or docs.

Keep examples generic and focused on patterns, not proprietary mechanisms.

When in doubt, prefer a more abstract or generic implementation.
