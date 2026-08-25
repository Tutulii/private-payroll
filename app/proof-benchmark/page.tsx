"use client";

import { useEffect, useState } from "react";
import { proveEncryptedPayroll, PayrollProofWorkerError } from "@/lib/proof/client";
import type { EncryptedVaultRecord, VaultPrincipalKeyPair } from "@/lib/crypto/vault";

type Fixture = {
  syntheticFixture: true;
  principal: VaultPrincipalKeyPair;
  encryptedWitness: EncryptedVaultRecord;
};

export default function ProofBenchmarkPage() {
  const [fixture, setFixture] = useState<Fixture | null>(null);
  const [stage, setStage] = useState("fixture-unavailable");
  const [error, setError] = useState("");
  const [result, setResult] = useState<{
    circuitSha256: string;
    provingTimeMs: number;
    publicInputCount: number;
    calldataCounts: [number, number];
    calldataHashes: [string, string];
  } | null>(null);

  useEffect(() => {
    fetch("/fixtures/encrypted-payroll-witness-v1.json", { cache: "no-store" })
      .then((response) => {
        if (!response.ok) throw new Error("fixture unavailable");
        return response.json() as Promise<Fixture>;
      })
      .then((loaded) => {
        if (!loaded.syntheticFixture) throw new Error("fixture invalid");
        setFixture(loaded);
        setStage("ready");
      })
      .catch(() => setStage("fixture-unavailable"));
  }, []);

  const prove = async () => {
    if (!fixture) return;
    setError("");
    setResult(null);
    try {
      const proof = await proveEncryptedPayroll({
        encryptedWitness: fixture.encryptedWitness,
        principal: fixture.principal,
        onProgress: setStage,
      });
      setResult({
        circuitSha256: proof.circuitSha256,
        provingTimeMs: proof.provingTimeMs,
        publicInputCount: proof.shards.reduce(
          (count, shard) => count + Object.keys(shard.publicInputs).length,
          0,
        ),
        calldataCounts: [proof.shards[0].proofCalldata.length, proof.shards[1].proofCalldata.length],
        calldataHashes: [proof.shards[0].calldataHash, proof.shards[1].calldataHash],
      });
      setStage("complete");
    } catch (proofError) {
      setError(proofError instanceof PayrollProofWorkerError ? proofError.message : "The proof benchmark failed.");
      setStage("failed");
    }
  };

  return (
    <div className="product-page" data-proof-stage={stage}>
      <section className="page-heading reveal reveal--one">
        <div>
          <span className="sticker sticker--blue">LOCAL ZK BENCHMARK</span>
          <h2>Prove payroll.<br /><em>Reveal nothing else.</em></h2>
          <p>This isolated production harness accepts only an encrypted synthetic witness. Payroll plaintext is decrypted and proved inside a browser Web Worker.</p>
        </div>
      </section>
      <section className="payroll-stage-card reveal reveal--two">
        <div className="payroll-stage__copy">
          <div className="stage-status"><span /> {stage.replaceAll("-", " ").toUpperCase()}</div>
          <h3>PayrollIntegrity v1</h3>
          <p>The worker self-verifies both linked UltraKeccakZKHonk shards and returns exactly 34 deployment-bound public inputs.</p>
          <button className="button button--ink" type="button" onClick={prove} disabled={!fixture || !["ready", "failed", "complete"].includes(stage)}>
            Generate local proof
          </button>
          {error && <p role="alert">{error}</p>}
          {result && (
            <div
              data-proof-result="verified"
              data-calldata-counts={result.calldataCounts.join(",")}
              data-calldata-hashes={result.calldataHashes.join(",")}
            >
              <strong>Proof verified and encoded locally</strong>
              <p>{result.publicInputCount} public inputs · {result.calldataCounts.join(" + ")} Starknet felts · {result.provingTimeMs} ms</p>
              <small>{result.circuitSha256}</small>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
