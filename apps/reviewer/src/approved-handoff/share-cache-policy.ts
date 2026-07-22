// SPDX-License-Identifier: Apache-2.0

export const maximumApprovedHandoffCacheFiles = 10;
export const maximumApprovedHandoffCacheAgeMilliseconds = 60 * 60 * 1000;
export const maximumApprovedHandoffShareFileBytes = 2 * 1_024 * 1_024;

const cacheFilenamePattern = /^tacua-handoff-[A-Za-z0-9_-]{1,64}-v[1-9][0-9]{0,15}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.(?:json|md)$/;

export type ApprovedHandoffCacheEntry = {
  readonly name: string;
  readonly isFile: boolean;
  readonly isDirectChild: boolean;
  readonly size: number;
  readonly lastModified: number | null;
};

export function isApprovedHandoffCacheFilename(name: string): boolean {
  return cacheFilenamePattern.test(name);
}

export function planApprovedHandoffCacheCleanup(
  entries: readonly ApprovedHandoffCacheEntry[],
  now: number,
  reserveSlots = 0,
): { readonly deleteNames: readonly string[]; readonly retainedNames: readonly string[] } {
  if (!Number.isSafeInteger(now) || now < 0 || !Number.isSafeInteger(reserveSlots) || reserveSlots < 0 || reserveSlots > maximumApprovedHandoffCacheFiles) {
    throw new Error("The approved-handoff cache cleanup parameters are invalid.");
  }
  const managed = entries.filter((entry) => (
    entry.isFile && entry.isDirectChild && isApprovedHandoffCacheFilename(entry.name)
  ));
  const deleteNames = new Set<string>();
  const retained = managed.filter((entry) => {
    const valid = entry.size >= 1
      && entry.size <= maximumApprovedHandoffShareFileBytes
      && entry.lastModified !== null
      && entry.lastModified <= now + 60_000
      && now - entry.lastModified <= maximumApprovedHandoffCacheAgeMilliseconds;
    if (!valid) deleteNames.add(entry.name);
    return valid;
  });
  retained.sort((left, right) => (right.lastModified ?? 0) - (left.lastModified ?? 0) || right.name.localeCompare(left.name));
  const limit = maximumApprovedHandoffCacheFiles - reserveSlots;
  for (const entry of retained.slice(limit)) deleteNames.add(entry.name);
  return {
    deleteNames: [...deleteNames],
    retainedNames: retained.slice(0, limit).map((entry) => entry.name),
  };
}
