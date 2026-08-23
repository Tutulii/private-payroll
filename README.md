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

- Private treasury and upcoming payroll summaries.
- Human and AI-agent recipient roster.
- Recent private payment activity.
- An MCP quick-connect surface for agent integrations.
- An animated payroll review flow.

The visual system uses warm paper tones, flat illustrated shapes, strong outlines, and restrained 2D motion. It intentionally avoids the neon, glass, and sci-fi conventions common in crypto products.

### Run locally

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

### Verify

```bash
npm run lint
npm run build
```

## License

MIT
