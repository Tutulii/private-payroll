<!-- BEGIN:nextjs-agent-rules -->

# This is NOT the Next.js you know

This version has breaking changes — APIs, conventions, and file structure may all differ from your training data. Read the relevant guide in `node_modules/next/dist/docs/` (resolved from this file's directory; in monorepos the `next` package may not be visible from the repo root) before writing any code. Heed deprecation notices.

This block is written and re-added by `next dev` — verify at `node_modules/next/dist/server/lib/generate-agent-files.js`. Removing it from a diff only re-creates the uncommitted change; committing it with your work keeps the tree clean.

<!-- END:nextjs-agent-rules -->

## PAYO completion rules

These rules are mandatory for every future task in this repository:

1. Never claim that PAYO is complete, fully implemented, production-ready, or 100% done from plans, scaffolding, source directories, interfaces, or isolated unit tests.
2. Before reporting a completion percentage or marking a roadmap item complete, reread `README.md` from `## Master implementation roadmap` through Phase 5 and reread all of `architecture.md`.
3. Compare every requirement with the actual integrated code path, positive and negative tests, and deployment evidence recorded in `docs/implementation-status.json`.
4. Run `npm run verify:status` for ordinary changes. Run `npm run verify:completion` before any 100% claim; it must pass together with every web, Noir, Garaga, Cairo, database, MCP, wallet, and Mainnet evidence gate described in `MASTER_PLAN.md`.
5. A mocked verifier, disabled feature, schema without integration, calculator without settlement, user-reported transaction without repository evidence, or external blocker is not complete.
6. When evidence is incomplete, say so explicitly and keep the requirement partial, missing, or blocked. Never weaken the requirement to improve the percentage.

The normative execution plan is `MASTER_PLAN.md`. The machine-readable source of current completion truth is `docs/implementation-status.json`.
