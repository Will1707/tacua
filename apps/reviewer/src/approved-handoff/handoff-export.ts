// SPDX-License-Identifier: Apache-2.0

import type { File } from "expo-file-system";
import * as Sharing from "expo-sharing";

import {
  cleanupApprovedHandoffShareCache,
  createApprovedHandoffShareFile,
} from "@/approved-handoff/share-cache";

export type ApprovedHandoffExportInput = {
  readonly title: string;
  readonly candidateId: string;
  readonly candidateVersion: number;
  readonly extension: "json" | "md";
  readonly bytes: Uint8Array;
  readonly mimeType: string;
  readonly uti: string;
};

export function prepareApprovedHandoffExport(): void {
  cleanupApprovedHandoffShareCache();
}

export async function exportApprovedHandoff(input: ApprovedHandoffExportInput): Promise<void> {
  if (!await Sharing.isAvailableAsync()) {
    throw new Error("File sharing is unavailable on this device.");
  }
  const sharedFile: File = createApprovedHandoffShareFile({
    candidateId: input.candidateId,
    candidateVersion: input.candidateVersion,
    extension: input.extension,
    bytes: input.bytes,
  });
  await Sharing.shareAsync(sharedFile.uri, {
    dialogTitle: `${input.title} · Tacua handoff`,
    mimeType: input.mimeType,
    UTI: input.uti,
  });
}
