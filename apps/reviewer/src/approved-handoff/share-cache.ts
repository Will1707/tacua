// SPDX-License-Identifier: Apache-2.0

import * as Crypto from "expo-crypto";
import { Directory, File, Paths } from "expo-file-system";

import {
  isApprovedHandoffCacheFilename,
  maximumApprovedHandoffCacheFiles,
  maximumApprovedHandoffShareFileBytes,
  planApprovedHandoffCacheCleanup,
} from "@/approved-handoff/share-cache-policy";

const cacheDirectoryName = "tacua-approved-handoffs-v1";

function cacheDirectory(): Directory {
  const directory = new Directory(Paths.cache, cacheDirectoryName);
  directory.create({ idempotent: true, intermediates: true });
  return directory;
}

function isManagedFile(entry: File | Directory, directory: Directory): entry is File {
  return entry instanceof File
    && isApprovedHandoffCacheFilename(entry.name)
    && entry.parentDirectory.uri === directory.uri
    && entry.uri === new File(directory, entry.name).uri;
}

function deleteManagedFile(file: File): void {
  if (file.exists) file.delete();
}

/**
 * Remove expired/oversized files and enforce a deterministic newest-first
 * bound. reserveSlots is used immediately before creating a new share file.
 */
export function cleanupApprovedHandoffShareCache(
  now = Date.now(),
  reserveSlots = 0,
): void {
  const directory = cacheDirectory();
  const entries = directory.list();
  const plan = planApprovedHandoffCacheCleanup(entries.map((entry) => ({
    name: entry.name,
    isFile: entry instanceof File,
    isDirectChild: entry instanceof File
      && entry.parentDirectory.uri === directory.uri
      && entry.uri === new File(directory, entry.name).uri,
    size: entry instanceof File ? entry.size : 0,
    lastModified: entry instanceof File ? entry.lastModified : null,
  })), now, reserveSlots);
  const managedByName = new Map(entries.filter((entry) => isManagedFile(entry, directory)).map((entry) => [entry.name, entry]));
  for (const name of plan.deleteNames) {
    const file = managedByName.get(name);
    if (file) deleteManagedFile(file);
  }

  const remaining = directory.list().filter((entry) => isManagedFile(entry, directory));
  if (remaining.length > maximumApprovedHandoffCacheFiles - reserveSlots) {
    throw new Error("Tacua could not safely bound the approved-handoff cache.");
  }
}

export function createApprovedHandoffShareFile(input: {
  readonly candidateId: string;
  readonly candidateVersion: number;
  readonly extension: "json" | "md";
  readonly bytes: Uint8Array;
}): File {
  if (input.bytes.byteLength < 1 || input.bytes.byteLength > maximumApprovedHandoffShareFileBytes) {
    throw new Error("The approved handoff is outside the safe share-file size.");
  }
  if (!Number.isSafeInteger(input.candidateVersion) || input.candidateVersion < 1) {
    throw new Error("The approved handoff version is invalid.");
  }
  cleanupApprovedHandoffShareCache(Date.now(), 1);
  const safeCandidateId = input.candidateId.replace(/[^A-Za-z0-9_-]/g, "_").slice(0, 64) || "ticket";
  const filename = `tacua-handoff-${safeCandidateId}-v${input.candidateVersion}-${Crypto.randomUUID()}.${input.extension}`;
  if (!isApprovedHandoffCacheFilename(filename)) throw new Error("Tacua could not create a safe handoff filename.");
  const directory = cacheDirectory();
  const file = new File(directory, filename);
  if (file.parentDirectory.uri !== directory.uri || file.uri !== new File(directory, filename).uri) {
    throw new Error("The approved handoff path escaped its dedicated cache.");
  }
  try {
    file.create({ overwrite: false });
    file.write(input.bytes);
    if (!file.exists || file.size !== input.bytes.byteLength || file.size > maximumApprovedHandoffShareFileBytes) {
      throw new Error("Tacua could not verify the cached handoff file.");
    }
    return file;
  } catch (error) {
    try { deleteManagedFile(file); } catch { /* best-effort rollback for an unshared partial file */ }
    throw error;
  }
}
