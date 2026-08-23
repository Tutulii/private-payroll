# Private Payroll

Run payroll and treasury disbursements on Starknet without publicly exposing employee salaries or linking every recipient to the company treasury.

Private Payroll is being built for the STRK20 Private Sprint. Employers can prepare payroll batches and pay team members through STRK20 shielded transfers. Employees receive private balances while the application provides clear payment status and an optional path for selective disclosure.

## Working human-payroll MVP

- Discover and connect a Starknet Wallet API signer (Ready works today).
- Detect and display Ready's Wallet API version, then query the shielded STRK token explicitly.
- Distinguish an unregistered account, zero balance, available balance, unsupported API, and read errors.
- Detect an unregistered pool account and hand it off to the one-time STRK20 setup flow before allowing shielding.
- Build up to 50 recipient transfers and submit them as one STRK20 wallet request.
- Track wallet approval, Sepolia confirmation, and the Starkscan receipt.
- Validate Starknet addresses, amounts, duplicate recipients, network, and treasury coverage before submission.

The browser flow is intentionally locked to Starknet Sepolia while it is being tested. Mainnet enablement comes after a successful end-to-end test with real Ready accounts.

Next: persistent payroll records, selective-disclosure exports, Mainnet enablement, recurring payroll contracts, and backend policy wallets for AI agents.

## Frontend

The current frontend is a responsive Next.js dashboard for a mixed human and AI-agent team. It includes:

- Overview (`/`) — private treasury, next payday, team, activity, and MCP connection summary.
- Payroll (`/payroll`) — live STRK20 treasury shielding and private batch execution, plus payroll planning and history.
- People & Agents (`/team`) — searchable recipient directory, compensation, privacy readiness, and scoped MCP access.
- Activity (`/activity`) — private audit trail, onchain transaction references, privacy coverage, and selective-disclosure receipts.
- Connect wallet (`/wallet`) — Ready wallet discovery for STRK20 signing, shielded balance and capability status, plus optional Privy identity.
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
NEXT_PUBLIC_STARKNET_RPC_URL=https://api.cartridge.gg/x/starknet/sepolia
```

Privy app secrets are server credentials. Never expose one through a `NEXT_PUBLIC_` variable or commit it to the repository. Rotate any secret that has been shared outside a secure secret manager.

Privy is the identity layer; it is not the human STRK20 signer. Human privacy actions use `WalletAccountV6` through Ready. Policy-controlled Starknet wallets for AI agents remain a later backend integration because their authorization and app secret cannot safely live in the browser.

### Try a private payroll

1. Install Ready and select Starknet Sepolia in the wallet.
2. Open `/wallet`, choose **Connect Ready**, and approve account access.
3. If the account is not registered, complete the linked one-time STRK20 setup and return to refresh the balance.
4. Open `/payroll#private-payroll` and shield a small amount of test STRK.
5. Add valid Starknet recipient addresses and amounts.
6. Approve the private payroll request in Ready and follow the Sepolia receipt link.

The application never requests or stores a recovery phrase, viewing key, or private key. Recipient names remain local component state in this frontend build; only addresses and atomic amounts are sent to Ready when the user explicitly approves the batch.

### Verify

```bash
npm run lint
npm run build
```

## License

MIT
