# Private Payroll

Run payroll and treasury disbursements on Starknet without publicly exposing employee salaries or linking every recipient to the company treasury.

Private Payroll is being built for the STRK20 Private Sprint. Employers can prepare payroll batches and pay team members through STRK20 shielded transfers. Employees receive private balances while the application provides clear payment status and an optional path for selective disclosure.

## Planned MVP

- Create and manage a payroll recipient list locally.
- Prepare a payroll batch with individual token amounts.
- Shield treasury funds and execute private employee payments through STRK20.
- Show batch progress without publishing individual salaries in the application UI.
- Export employee payment records for voluntary disclosure and accounting.
- Document precisely what STRK20 hides and what remains visible onchain.

## Frontend

The current frontend is a responsive Next.js dashboard for a mixed human and AI-agent team. It includes:

- Overview (`/`) — private treasury, next payday, team, activity, and MCP connection summary.
- Payroll (`/payroll`) — upcoming payroll review, funding readiness, status filters, payroll history, and schedule.
- People & Agents (`/team`) — searchable recipient directory, compensation, privacy readiness, and scoped MCP access.
- Activity (`/activity`) — private audit trail, onchain transaction references, privacy coverage, and selective-disclosure receipts.
- Connect wallet (`/wallet`) — Privy authentication, supported external-wallet connection, wallet identity, and agent-wallet architecture guidance.
- An MCP quick-connect surface for agent integrations.
- An animated payroll review flow.

The visual system uses warm paper tones, flat illustrated shapes, strong outlines, and restrained 2D motion. It intentionally avoids the neon, glass, and sci-fi conventions common in crypto products.

### Run locally

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

### Privy configuration

Copy `.env.example` to `.env.local` and add the public Privy App ID:

```bash
NEXT_PUBLIC_PRIVY_APP_ID=your-privy-app-id
```

Privy app secrets are server credentials. Never expose one through a `NEXT_PUBLIC_` variable or commit it to the repository. Rotate any secret that has been shared outside a secure secret manager.

Privy’s React external-wallet connector currently covers EVM and Solana wallets. The STRK20 transaction flow will use a Starknet-native signer, while policy-controlled Starknet wallets for AI agents can use Privy’s server APIs in a later backend integration.

### Verify

```bash
npm run lint
npm run build
```

## License

MIT
