// SPDX-License-Identifier: Apache-2.0

export type EvidencePreviewDigest = (bytes: Uint8Array) => Promise<string>;

export type EvidencePreviewIntegrityCode =
  | "INVALID_PREVIEW_DIGEST"
  | "PREVIEW_LENGTH_MISMATCH"
  | "PREVIEW_DIGEST_MISMATCH";

export class EvidencePreviewIntegrityError extends Error {
  readonly code: EvidencePreviewIntegrityCode;

  constructor(code: EvidencePreviewIntegrityCode) {
    super(code);
    this.name = "EvidencePreviewIntegrityError";
    this.code = code;
  }
}

/**
 * Verifies the bytes themselves, not merely a backend-supplied digest header.
 * The digest function is injected so this trust check remains deterministic in
 * Node tests while the app uses the native Expo Crypto implementation.
 */
export async function verifyEvidencePreviewBytes(options: {
  readonly bytes: Uint8Array;
  readonly declaredLength: number;
  readonly expectedDigest: string;
  readonly digest: EvidencePreviewDigest;
}): Promise<void> {
  if (!/^sha256:[a-f0-9]{64}$/.test(options.expectedDigest)) {
    throw new EvidencePreviewIntegrityError("INVALID_PREVIEW_DIGEST");
  }
  if (
    !Number.isSafeInteger(options.declaredLength)
    || options.declaredLength < 1
    || options.bytes.byteLength !== options.declaredLength
  ) {
    throw new EvidencePreviewIntegrityError("PREVIEW_LENGTH_MISMATCH");
  }
  if (await options.digest(options.bytes) !== options.expectedDigest) {
    throw new EvidencePreviewIntegrityError("PREVIEW_DIGEST_MISMATCH");
  }
}
