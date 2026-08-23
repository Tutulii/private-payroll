# Native USDC Mainnet evidence

This record distinguishes facts visible on Starknet from private facts that Ready does not reveal publicly. A private transfer's asset, recipient, and amount cannot be decoded from its public receipt. Visible withdrawals can be fee recovery and do not identify the private asset.

## Verified native-USDC shield

- Transaction: `0x374e2265720ca99fe20ad2cb8bb9a5f25490512dab293bebff39eabe0b94b63`
- Ready account: `0x038c1d4e372a3cdf605a0c06d944b046c7f4d7923922001f9366b5d000aa3871`
- Block: `13756837`
- Receipt: `SUCCEEDED`, `ACCEPTED_ON_L2`
- Public native-USDC debit: `250000` atomic units (`0.25 USDC`)
- Pool USDC fee withdrawal: `201092` atomic units (`0.201092 USDC`)
- Implied private shield amount: `48908` atomic units (`0.048908 USDC`)
- Pool evidence: native-USDC `Deposit`, `EncNoteCreated`, and native-USDC `Withdrawal` events

This proves that Ready can shield Circle native USDC through the live Mainnet pool. It also disproves PAYO's earlier assumption that this path pays the privacy fee separately in public STRK.

## Verified private STRK20 transaction with Ready/user attestation

- Transaction: `0x6c6b509d0243ad49f7abca7b5fbbf9e4be1dd7f6c02f15e3b42420131f7866`
- Public submitting account: `0x022391d617f10d3563005c825845b42b218b55b2af2202201db5710ceceb40e7`
- Block: `13757530`
- Receipt: `SUCCEEDED`, `ACCEPTED_ON_L2`
- Pool evidence: `NoteUsed`, `EncNoteCreated`, and `Withdrawal`
- Public fee-recovery withdrawal token: STRK (`0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d`)
- Ready/user attestation: cross-account private USDC transfer to the user's registered Ready account
- Publicly hidden by design: transferred asset, recipient, and amount

The STRK withdrawal does not imply that STRK was privately transferred. It is fee recovery alongside private note consumption and creation. Because Ready does not expose a viewing key or SettlementMatch evidence, the USDC and recipient details are explicitly wallet/user-attested rather than falsely described as publicly decoded.

## Gate decision

Phase 0 native-USDC compatibility is complete at the `wallet confirmed` evidence level:

- the shield receipt publicly proves a native-USDC deposit into the live pool;
- the second receipt publicly proves private notes were consumed and created;
- Ready/user attestation binds the hidden operation to cross-account USDC;
- no claim of public settlement reconciliation is made.

This does not complete SettlementMatch or prove the private recipient/amount to a third party. Those remain later architecture requirements for direct Privacy SDK accounts with locally controlled viewing-key evidence.
