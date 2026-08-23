# PAYO MCP server

The MCP adapter gives agents structured payroll operations without exposing a generic wallet or contract-call tool. Every call reloads a revocable, signed capability from PAYO before it runs.

## Start

```bash
PAYO_API_URL=http://localhost:3000 \
PAYO_API_ACCESS_TOKEN='<short-lived Privy access token>' \
PAYO_CAPABILITY_ID='<registered capability id>' \
PAYO_CAPABILITY_ISSUER_PUBLIC_KEY='<pinned Ed25519 public key, base64>' \
npm run mcp
```

Available tools:

- `payo_get_capability`
- `payo_list_due_obligations`
- `payo_draft_run`
- `payo_validate_run`
- `payo_request_execution`
- `payo_get_run_status`
- `payo_get_receipt`
- `payo_create_disclosure`

`payo_request_execution` queues threshold-crossing requests for approval. An allowed autonomous request is reported as `delegated_signer_not_configured` until PAYO has a purpose-built account policy/session-key signer; the MCP server never accepts arbitrary targets or calldata and never silently falls back to a broad wallet key.
