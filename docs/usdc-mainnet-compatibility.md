# Native USDC Mainnet compatibility gate

PAYO must not enable native USDC payroll until this gate passes with Ready and the live STRK20 pool. The token under test is Circle native USDC at `0x033068f6539f8e6e6b131e6b2b814e6c34a5224bc66947c47dab9dfee93b35fb` with six decimals. Bridged USDC does not satisfy the gate.

## Required wallet procedure

1. Connect an already registered Ready account on Starknet Mainnet and record the detected Wallet API version.
2. Shield a deliberately small native-USDC amount and record its atomic amount and successful transaction hash.
3. Privately transfer part of only that test amount and record its successful transaction hash. Record asset, recipient relationship, and amount only as an explicit Ready/user attestation; those values are intentionally not public.
4. Do not submit unrelated wallet transactions in the same blocks as either test transaction; the validator derives exact before/after public balances from historical Mainnet state.
5. Confirm that the native-USDC shield delta uses six decimals. For the private transfer, confirm `NoteUsed` and `EncNoteCreated`; never infer its hidden asset from a visible fee-recovery `Withdrawal`.
6. Copy `evidence/usdc-mainnet.example.json` to `evidence/usdc-mainnet.json`, replace every placeholder, and run `npm run verify:usdc`.

Both transactions have real value and require explicit confirmation in Ready. The committed evidence intentionally reveals the account, hashes, and tiny test amounts, but never the private recipient or the wallet's total private balance. Never paste a wallet key, recovery phrase, viewing key, private recipient, or private treasury balance into the evidence file.

## Pass criteria

- Ready reports Wallet API 0.10.3 or newer.
- Mainnet RPC reports both transactions accepted and successful.
- The shield receipt contains native-USDC `Deposit`, `EncNoteCreated`, and native-USDC `Withdrawal` pool events.
- The private-transfer receipt contains `NoteUsed` and `EncNoteCreated`. The Ready/user attestation identifies the hidden asset and recipient relationship without claiming public verification.
- The native-USDC contract reports six decimals.
- Historical on-chain public-USDC deltas match the deliberately small shield amount. Private-transfer asset, amount, and recipient remain hidden.
- Both receipts report a Starknet fee unit, but no public-STRK debit is assumed when Ready uses sponsorship or token-fee recovery.
- `NEXT_PUBLIC_ENABLE_EXPERIMENTAL_USDC` stays `false` until this evidence is committed and reviewed.
