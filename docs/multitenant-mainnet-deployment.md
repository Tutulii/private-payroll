# Multi-tenant PAYO Mainnet deployment

This runbook replaces the original singleton-admin obligation topology. It does
not replace the live STRK20 pool or the already deployed proof-bound verifier
profiles.

## Topology

- a fresh `PayoPolicyRegistry`, administered by the limited-purpose PAYO relayer;
- a fresh `PayoTenantObligationRootRegistry`, where the scheduling Ready account
  owns its commitment and the protocol administrator has emergency revocation
  only;
- a fresh `PayoPayrollSeal` bound immutably to those two registries, Starknet
  Mainnet, and the live STRK20 pool;
- the existing verified v1, v2, claim, and remediation verifier bundles.

The policy registry's FX publisher is the relayer. `/api/v1/fx-publications`
accepts a publication only after authenticating the tenant, validating an
expiring catalog ticket, and checking both proof shards through the registered
on-chain verifier at a pinned block. PostgreSQL advisory locks serialize all
transactions sent by the shared relayer account.

## Required gates

Run these before any write:

```bash
npm ci
npm test
npm run typecheck
npm run lint
npm run build
cd contracts && scarb test && scarb build && cd ..
npm run multitenant:mainnet:plan
npm run multitenant:mainnet:estimate
```

Database tests must use a disposable migrated PostgreSQL database. Never point
`PAYO_TEST_DATABASE_URL` at production.

The plan command fixes deterministic addresses from the compiled class hashes,
constructor calldata, and reviewed salts. Every later command rebuilds that
plan and refuses stale artifacts.

## Writes

Use the three separate confirmation phrases only after reviewing the previous
receipt and read-back:

```bash
PAYO_MULTITENANT_MAINNET_CONFIRM=DECLARE_PAYO_MULTITENANT_MAINNET \
  npm run multitenant:mainnet:declare

PAYO_MULTITENANT_MAINNET_CONFIRM=DEPLOY_PAYO_MULTITENANT_MAINNET \
  npm run multitenant:mainnet:deploy

PAYO_MULTITENANT_MAINNET_CONFIRM=ACTIVATE_PAYO_MULTITENANT_MAINNET \
  npm run multitenant:mainnet:activate

npm run multitenant:mainnet:verify
```

Each action is restart-safe: it reads Mainnet before submitting and records
already completed work instead of repeating it. Deployment evidence is written
under `circuits/payroll_integrity/target/` and contains no private key.

## Runtime cutover

Update both private server and browser build-time values together:

- `PAYO_SEAL_ADDRESS` / `NEXT_PUBLIC_PAYO_SEAL_ADDRESS`;
- `PAYO_POLICY_REGISTRY_ADDRESS` / `NEXT_PUBLIC_PAYO_POLICY_REGISTRY_ADDRESS`;
- `PAYO_OBLIGATION_REGISTRY_ADDRESS` / `NEXT_PUBLIC_PAYO_OBLIGATION_REGISTRY_ADDRESS`;
- `PAYO_INDEX_CONTRACT_ADDRESS` and a new index consumer name.

Rebuild the web image because `NEXT_PUBLIC_*` values are embedded by Next.js.
Keep the old addresses in the historical evidence documents. After cutover,
verify the deployed class hashes and registry bindings again, then run a small
payroll from a non-relayer Ready account before calling the migration live.
