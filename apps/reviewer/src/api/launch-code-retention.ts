// SPDX-License-Identifier: Apache-2.0

export const maximumLocalLaunchCodeRetentionMilliseconds = 5 * 60 * 1_000;

/**
 * Keep an unexchanged code only long enough for an immediate retry. The
 * backend remains authoritative for expiry, while this local ceiling prevents
 * a skewed device clock from retaining the credential in React state for an
 * unbounded period.
 */
export function launchCodeRetentionMilliseconds(expiresAt: string, now = Date.now()): number {
  const expiresAtMilliseconds = Date.parse(expiresAt);
  if (!Number.isFinite(expiresAtMilliseconds) || !Number.isFinite(now)) return 0;
  return Math.max(0, Math.min(
    expiresAtMilliseconds - now,
    maximumLocalLaunchCodeRetentionMilliseconds,
  ));
}
