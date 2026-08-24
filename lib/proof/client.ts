import type { EncryptedVaultRecord, VaultPrincipalKeyPair } from "@/lib/crypto/vault";
import type {
  ProofWorkerFailure,
  ProofWorkerRequest,
  ProofWorkerResponse,
  ProofWorkerSuccess,
} from "./protocol";

export type ProofProgressListener = (stage: Extract<ProofWorkerResponse, { type: "proof-progress" }>["stage"]) => void;

export class PayrollProofWorkerError extends Error {
  constructor(readonly code: ProofWorkerFailure["code"], message: string) {
    super(message);
    this.name = "PayrollProofWorkerError";
  }
}

/** Main-thread API intentionally accepts ciphertext only; plaintext witness input is not supported. */
export function proveEncryptedPayroll(input: {
  encryptedWitness: EncryptedVaultRecord;
  principal: VaultPrincipalKeyPair;
  onProgress?: ProofProgressListener;
  timeoutMs?: number;
}): Promise<ProofWorkerSuccess> {
  const worker = new Worker(new URL("./payroll-proof.worker.ts", import.meta.url), { type: "module" });
  const requestId = crypto.randomUUID();
  const timeoutMs = input.timeoutMs ?? 30 * 60_000;
  const request: ProofWorkerRequest = {
    version: 1,
    type: "prove-payroll-integrity",
    requestId,
    encryptedWitness: input.encryptedWitness,
    principal: input.principal,
  };

  return new Promise((resolve, reject) => {
    const timer = window.setTimeout(() => {
      worker.terminate();
      reject(new PayrollProofWorkerError("PROVING_FAILED", "Local proof generation timed out."));
    }, timeoutMs);
    const finish = () => {
      window.clearTimeout(timer);
      worker.terminate();
    };
    worker.onerror = () => {
      finish();
      reject(new PayrollProofWorkerError("PROVING_FAILED", "The local proof worker stopped unexpectedly."));
    };
    worker.onmessage = (event: MessageEvent<ProofWorkerResponse>) => {
      const response = event.data;
      if (response.requestId !== requestId) return;
      if (response.type === "proof-progress") {
        input.onProgress?.(response.stage);
      } else if (response.type === "proof-failed") {
        finish();
        reject(new PayrollProofWorkerError(response.code, response.message));
      } else {
        finish();
        resolve(response);
      }
    };
    worker.postMessage(request);
  });
}
