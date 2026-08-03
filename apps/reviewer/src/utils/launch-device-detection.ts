// SPDX-License-Identifier: Apache-2.0

export type BrowserDeviceSnapshot = {
  readonly maxTouchPoints?: number;
  readonly userAgent?: string;
};

export function isLikelyIOSBrowser(snapshot: BrowserDeviceSnapshot): boolean {
  const userAgent = snapshot.userAgent ?? "";
  return /(?:iPad|iPhone|iPod)/iu.test(userAgent)
    || (
      /Macintosh/iu.test(userAgent)
      && (snapshot.maxTouchPoints ?? 0) > 1
    );
}
