import type { TrustLevel } from "./index.js";

export type AttestationEvidence = {
  plugin: string;
  trustLevel: TrustLevel;
  softwareGeneHash: string;
  evidence: Record<string, unknown>;
  degraded?: boolean;
  degradeReason?: string;
};

export type AttestationPlugin = {
  id: string;
  /** Attempt attestation; throw or return null to degrade */
  attest(input: {
    softwareGeneHash: string;
    agentName?: string;
  }): Promise<AttestationEvidence | null> | AttestationEvidence | null;
};

/** L0 software — always available */
export const softwarePlugin: AttestationPlugin = {
  id: "software",
  attest({ softwareGeneHash }) {
    return {
      plugin: "software",
      trustLevel: "software",
      softwareGeneHash,
      evidence: { kind: "software_hash", note: "software path can be mocked" },
    };
  },
};

/** L1 cloud remote attestation (plugin stub — requires cloud provider wiring) */
export const cloudAttestPlugin: AttestationPlugin = {
  id: "cloud_attest",
  async attest({ softwareGeneHash }) {
    const enabled = process.env.JIAOZI_CLOUD_ATTEST === "1";
    if (!enabled) return null;
    // Placeholder: real impl would call cloud TEE/enclave APIs
    return {
      plugin: "cloud_attest",
      trustLevel: "cloud_attest",
      softwareGeneHash,
      evidence: { kind: "cloud_remote", provider: process.env.JIAOZI_CLOUD_PROVIDER ?? "stub" },
    };
  },
};

/** L2 local TEE */
export const teePlugin: AttestationPlugin = {
  id: "tee",
  async attest({ softwareGeneHash }) {
    const enabled = process.env.JIAOZI_TEE === "1";
    if (!enabled) return null;
    return {
      plugin: "tee",
      trustLevel: "tee",
      softwareGeneHash,
      evidence: { kind: "tee_quote", note: "stub — wire SGX/TrustZone SDK in deploy" },
    };
  },
};

/** L2 TPM */
export const tpmPlugin: AttestationPlugin = {
  id: "tpm",
  async attest({ softwareGeneHash }) {
    const enabled = process.env.JIAOZI_TPM === "1";
    if (!enabled) return null;
    return {
      plugin: "tpm",
      trustLevel: "tpm",
      softwareGeneHash,
      evidence: { kind: "tpm_quote", note: "stub — wire TPM2 tools in deploy" },
    };
  },
};

const DEFAULT_CHAIN: AttestationPlugin[] = [
  tpmPlugin,
  teePlugin,
  cloudAttestPlugin,
  softwarePlugin,
];

/**
 * Try plugins from highest trust to lowest; degrade to software when absent.
 */
export async function runAttestationChain(
  input: { softwareGeneHash: string; agentName?: string },
  plugins: AttestationPlugin[] = DEFAULT_CHAIN,
): Promise<AttestationEvidence> {
  let higherUnavailable = false;
  for (const plugin of plugins) {
    try {
      const result = await plugin.attest(input);
      if (result) {
        if (higherUnavailable && result.trustLevel === "software") {
          return {
            ...result,
            degraded: true,
            degradeReason: "no hardware/cloud plugin available",
          };
        }
        return result;
      }
      if (plugin.id !== "software") higherUnavailable = true;
    } catch {
      if (plugin.id !== "software") higherUnavailable = true;
    }
  }
  return {
    plugin: "software",
    trustLevel: "software",
    softwareGeneHash: input.softwareGeneHash,
    evidence: { kind: "software_hash" },
    degraded: true,
    degradeReason: "no hardware/cloud plugin available",
  };
}
