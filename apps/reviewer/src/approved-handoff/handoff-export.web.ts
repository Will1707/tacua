// SPDX-License-Identifier: Apache-2.0

import {
  maximumApprovedHandoffShareFileBytes,
} from "./share-cache-policy.ts";

import type { ApprovedHandoffExportInput } from "./handoff-export";

export type ApprovedHandoffDownload = {
  readonly blob: Blob;
  readonly filename: string;
};

export function prepareApprovedHandoffExport(): void {
  // Web exports use a short-lived object URL and do not create a persistent cache.
}

export function createApprovedHandoffDownload(
  input: ApprovedHandoffExportInput,
): ApprovedHandoffDownload {
  if (input.bytes.byteLength < 1 || input.bytes.byteLength > maximumApprovedHandoffShareFileBytes) {
    throw new Error("The approved handoff is outside the safe download size.");
  }
  if (!Number.isSafeInteger(input.candidateVersion) || input.candidateVersion < 1) {
    throw new Error("The approved handoff version is invalid.");
  }
  const safeCandidateId = input.candidateId.replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 64) || "ticket";
  const filename = `tacua-handoff-${safeCandidateId}-v${input.candidateVersion}.${input.extension}`;
  const copy = new Uint8Array(new ArrayBuffer(input.bytes.byteLength));
  copy.set(input.bytes);
  return {
    blob: new Blob([copy], { type: input.mimeType }),
    filename,
  };
}

export async function exportApprovedHandoff(input: ApprovedHandoffExportInput): Promise<void> {
  if (typeof document === "undefined") {
    throw new Error("Browser file download is unavailable.");
  }
  const download = createApprovedHandoffDownload(input);
  const url = URL.createObjectURL(download.blob);
  const anchor = document.createElement("a");
  try {
    anchor.href = url;
    anchor.download = download.filename;
    anchor.rel = "noopener";
    anchor.style.display = "none";
    document.body.append(anchor);
    anchor.click();
  } finally {
    anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }
}
