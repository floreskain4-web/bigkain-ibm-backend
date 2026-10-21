---
name: backend-work
description: Repository-specific guidance for changing or testing this BigKain Node.js/Express Bitcoin verification backend. Use when editing server.js, signer.js, market.js, verification, endpoints, policies, or their tests.
---
# Backend work

- Read `README.md`, relevant implementation modules, and adjacent `test/*.test.js` before changing behavior. `package.json` defines Node >=18 and `npm test` runs `node --test test/*.test.js`.
- Preserve this service's non-custodial boundary and established API contracts. Keep market-data routes read-only; treat ownership challenges as single-use and time-limited; do not log signatures, PSBTs, message contents, credentials, or key material.
- Prefer focused changes with regression tests. Use synthetic fixtures and injected/mocked dependencies. Do not install dependencies, invoke live endpoints, deploy, or alter CI/dependencies unless specifically authorized.
- Check `git diff --check` and run only tests that are clearly offline and safe; report what was and was not run. Treat existing signing or signed-PSBT validation capabilities as legacy/out of scope, not as permission to expand them. Follow the absolute restrictions in `AGENTS.md`, `CLAUDE.md`, and `.github/copilot-instructions.md`.
