# Phase 2 Mainnet deployment runbook

This runbook covers the PAYO Phase 2 contract topology. It does not authorize a
Mainnet transaction. The mutation commands refuse to run unless their exact
confirmation phrase is supplied, and they require fee simulation before every
declaration, deployment, or baseline activation transaction.

Never paste a Ready recovery phrase or unrestricted wallet key into PAYO. Use a
separate fee-funded deployment account, inject its key from a temporary secret
environment, and clear that environment after the receipts are recorded. The
planned administrator should be a multisig for a production release.

## 1. Rebuild and test the exact artifacts

Use the versions pinned in `toolchains.lock.json`:

```bash
cd contracts/integrity_verifier
scarb build
snforge test
cd ..
scarb build
snforge test
cd ..
npm run phase2:devnet:check-artifacts
```

The final command fails if a deploy artifact is missing or older than its Cairo
source package. The Mainnet planner also recomputes and records each Sierra class
hash, compiled-class hash, and SHA-256 artifact digest.

## 2. Produce a read-only Mainnet plan

```bash
PAYO_MAINNET_ADMIN_ADDRESS=0x... \
STARKNET_RPC_URL=https://your-mainnet-rpc \
npm run phase2:mainnet:plan
```

The plan is written to the ignored
`circuits/payroll_integrity/target/payo-mainnet-plan.json`. Review all five class
hashes, constructor arguments, deterministic addresses, the canonical STRK20
pool, and the live declared/deployed state. The planner refuses a non-Mainnet
RPC or an address collision with a different class.

The topology is:

1. generated proof-bound Garaga verifier;
2. two-shard bundle verifier bound to that generated verifier;
3. policy/FX/verifier registry bound to the administrator;
4. authoritative obligation-root registry bound to the administrator; and
5. Payroll Seal bound to the canonical STRK20 Mainnet pool, both registries,
   and `SN_MAIN`.

## 3. Declare and deploy after explicit approval

### Ready wallet operator (recommended for the existing PAYO treasury admin)

Run the application locally, open `http://localhost:3000/deployment`, connect
Ready on Mainnet, verify the displayed administrator address, and type the exact
confirmation phrase. The page loads only the freshly rebuilt local artifacts,
recomputes their class hashes in the browser, asks Ready to simulate and approve
each missing declaration, batches the deterministic deployments, and reads all
class and constructor bindings back through RPC. It never requests or receives a
wallet key.

The artifact endpoint is disabled by default in a production build. A deployment
operator who intentionally hosts this route must temporarily set
`PAYO_ENABLE_DEPLOYMENT_OPERATOR=true`; a local `next dev` operator does not need
that flag. Disable it again immediately after deployment.

After the topology verifies, use **Schedule baseline** on the same page. PAYO
computes the exact canonical policy-catalog root used by the circuit and asks
Ready to activate that root and proof version 1 in the confirming block.

### Isolated command-line deployer

Do not put these variables in `.env.local`, shell history, CI logs, or the
repository. Use a temporary secret environment supplied by the deployment
operator:

```bash
PAYO_MAINNET_PLAN_PATH=circuits/payroll_integrity/target/payo-mainnet-plan.json \
PAYO_MAINNET_DEPLOYER_ADDRESS=0x... \
PAYO_MAINNET_DEPLOYER_PRIVATE_KEY=<temporary-secret> \
PAYO_MAINNET_CONFIRM=DEPLOY_PAYO_MAINNET \
STARKNET_RPC_URL=https://your-mainnet-rpc \
npm run phase2:mainnet:deploy
```

By default the deployer must equal the planned administrator. A separate
deployer is accepted only when
`PAYO_MAINNET_REQUIRE_ADMIN_DEPLOYER=false` is also explicit. Classes already
declared and predicted contracts already deployed with the exact expected class
are safely skipped. Unexpected state fails closed.

The script simulates fees, waits for every receipt, reads every deployed class
hash back at a pinned Mainnet block, and checks the verifier, administrator,
publisher, pool, and registry bindings. Evidence is written to the ignored
`circuits/payroll_integrity/target/payo-mainnet-deployment.json`.

## 4. Schedule the baseline policy and verifier

Review the canonical policy-catalog root before approving:

```bash
PAYO_MAINNET_PLAN_PATH=circuits/payroll_integrity/target/payo-mainnet-plan.json \
PAYO_MAINNET_DEPLOYER_ADDRESS=0x... \
PAYO_MAINNET_DEPLOYER_PRIVATE_KEY=<temporary-secret> \
PAYO_POLICY_ROOT=0x... \
PAYO_MAINNET_CONFIRM=SCHEDULE_PAYO_MAINNET_BASELINE \
STARKNET_RPC_URL=https://your-mainnet-rpc \
npm run phase2:mainnet:schedule
```

This activates proof mode `PRECOMMIT` / version `1` and the policy root when the
transaction confirms. The initial constrained FX publisher is the planned
administrator. A different service publisher can be scheduled and activated
immediately through the contract's two-step rotation before it publishes
short-lived FX roots.

Each exact payroll obligation root activates in its confirming transaction.
Fresh FX roots are published for only the remaining lifetime of the Pragma
observation, capped at one hour.

## 5. Configure and verify the application

After deployment and activation, set:

```bash
PAYO_CHAIN_ID=0x534e5f4d41494e
PAYO_SEAL_ADDRESS=0x...
NEXT_PUBLIC_PAYO_SEAL_ADDRESS=0x...
NEXT_PUBLIC_PAYO_POLICY_REGISTRY_ADDRESS=0x...
NEXT_PUBLIC_PAYO_OBLIGATION_REGISTRY_ADDRESS=0x...
PAYO_INDEX_CONTRACT_ADDRESS=0x...
```

Then run:

```bash
npm run phase2:mainnet:verify
npm run build
```

Finally execute deliberately small Ready-wallet STRK-only, native-USDC-only,
and mixed batches. Record transaction hashes and RPC receipts without publishing
private recipients or amounts. A Ready-backed run stops honestly at `confirmed`;
it is not `reconciled` because Ready does not expose the viewing-key evidence
needed for `SettlementMatch`.

## 6. Run the durable backend and proof relayer

Use a separately backed-up production PostgreSQL database and a secret manager.
Never point `PAYO_TEST_DATABASE_URL` at the production database: the integration
suite intentionally truncates its isolated test schema between cases.

```bash
npm run db:migrate
npm run phase2:relayer:status
npm run phase2:relayer:estimate
```

The proof relayer is a dedicated, fee-only OpenZeppelin account. It never holds
or approves payroll assets. Fund the exact address printed by `status`, review
the deployment estimate, and deploy only with the explicit confirmation:

```bash
PAYO_RELAYER_CONFIRM=DEPLOY_PAYO_RELAYER_MAINNET \
npm run phase2:relayer:deploy
```

The command derives the configured address from the private key, refuses a
non-Mainnet RPC, checks the pinned account class, estimates before mutation,
waits for confirmation, and reads the deployed class hash back. Store
`PAYO_PROOF_RELAYER_PRIVATE_KEY`, `DATABASE_URL`, and `PAYO_WORKER_SECRET` only
as server secrets. Normal PAYO authentication verifies ES256 Privy access tokens
against the app-bound public HTTPS JWKS and does not require an App Secret. If a
future privileged Privy wallet/user API needs a secret, it must be a freshly
rotated value that has never appeared in source, logs, or chat.

Run the application and worker runner as separately supervised processes:

```bash
npm run start
npm run workers
```

The worker runner executes non-overlapping confirmation, proof-verification,
and reorg-aware indexer leases with bounded exponential backoff. Configure the
indexer from the seal deployment block, and use a dedicated RPC plan in a
hosted production environment:

```bash
PAYO_INDEX_CHAIN_ID=SN_MAIN
PAYO_INDEX_CONSUMER=payo-seal
PAYO_INDEX_CONTRACT_ADDRESS=0x...
PAYO_INDEX_FROM_BLOCK=<seal-deployment-block>
PAYO_INDEX_BATCH_SIZE=100
PAYO_INDEX_FINALITY_LAG=2
PAYO_INDEX_PREFETCH_CONCURRENCY=4
PAYO_INDEX_MAX_REORG_DEPTH=128
```

At the 2026-08-25 Mainnet gas price, a direct proof-shard verification estimated
about 62 STRK and a relayer account deployment about 0.16 STRK. These are live
estimates, not fixed fees. Alert on relayer balance, failed/permanent jobs,
indexer lag, and RPC rate limiting; replenish only the fee account.
