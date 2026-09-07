# PAYO Security Policy

PAYO handles payroll metadata, encrypted records, wallet approvals, proof witnesses, and Mainnet contract interactions. Please report suspected vulnerabilities privately so maintainers can investigate before details become public.

## Report privately

Use [GitHub Security Advisories](https://github.com/Tutulii/private-payroll/security/advisories/new) and include:

- the affected route, package, circuit, contract, or deployed address;
- the preconditions and impact;
- minimal reproduction steps or a proof of concept;
- whether Mainnet funds or private payroll data may be at risk; and
- any suggested mitigation.

Do not include real recovery material, private keys, viewing keys, access tokens, employee data, or unredacted payroll exports. If proof requires sensitive data, describe how maintainers can reproduce it with synthetic values.

## High-priority scope

Reports are especially useful when they involve:

- authorization or tenant-isolation bypass;
- plaintext leakage from the encrypted vault or proof pipeline;
- signature, session, recovery, or replay flaws;
- commitment, Merkle, nullifier, arithmetic, policy, or schedule inconsistencies;
- verifier, bundle, registry, or seal bypass;
- transaction substitution, duplicate payment, or false-confirmation behavior;
- unrestricted behavior at the MCP, policy-account, or isolated-signer boundary;
- private-exit route substitution or misleading privacy claims; or
- dependency or build-chain compromise affecting shipped artifacts.

## Current security boundary

- PAYO is non-custodial; settlement remains under Ready or the restricted policy account.
- Payroll records are encrypted in the client before persistence.
- The configured hosted prover decrypts a proof witness in volatile job memory and is trusted not to retain or log it. A self-hosted prover can remove this operator trust.
- Ready-backed flows cannot produce SettlementMatch evidence because the wallet does not expose the required viewing key to the dapp.
- Mainnet timing, contract interaction, calldata size, and possibly the submitting account remain observable.
- The contracts and circuits are experimental and have not received an independent production security audit.

## Coordinated disclosure

Please allow maintainers time to reproduce and fix a report before publishing it. The project will credit reporters when requested and when disclosure does not expose private user data or an active exploit.

The presence of this policy does not create a warranty or security guarantee. The repository is provided under the terms of the [MIT License](./LICENSE).
