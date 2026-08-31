# PAYO MCP server

The MCP adapter gives agents structured payroll operations without exposing a generic wallet or contract-call tool. Every call reloads a revocable, signed capability from PAYO before it runs.

## Start

PAYO currently uses a local `stdio` MCP transport. Run it on the same machine
as the AI client; it calls the hosted PAYO API over HTTPS and does not need a
separate Fly.io machine. A remote HTTP/SSE transport can be added later for
browser or hosted-agent clients without changing the capability model.

```bash
PAYO_API_URL=https://private-payroll.fly.dev \
PAYO_API_ACCESS_TOKEN='<short-lived Ready session token>' \
PAYO_CAPABILITY_ID='<registered capability id>' \
PAYO_CAPABILITY_ISSUER_PUBLIC_KEY='<pinned Ed25519 public key, base64>' \
npm run mcp
```

For local development, `PAYO_API_URL=http://localhost:3000` is accepted.
Remote plaintext HTTP, credential-bearing URLs, query strings, and fragments
are rejected. Keep the Ready session token in the AI client's secret/env
configuration; never place it in prompts or commit it to the repository.

Available tools:

- `payo_get_capability`
- `payo_list_due_obligations`
- `payo_draft_run`
- `payo_validate_run`
- `payo_request_execution`
- `payo_get_run_status`
- `payo_get_receipt`
- `payo_create_disclosure`

`payo_request_execution` accepts only versioned payment intents. Requests under
an explicitly autonomous capability are processed by PAYO's restricted policy
account; all other requests wait for human review and Ready approval. The MCP
server never accepts arbitrary targets, selectors, calldata, proofs, or signer
parameters, and it never falls back to a broad wallet key.

Run the transport/adversarial suite with `npm run test:mcp`.
