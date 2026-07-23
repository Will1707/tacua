// SPDX-License-Identifier: Apache-2.0

export function effectiveReviewerScheme(
  platform: string,
  preferred: "dark" | "light" | "unspecified" | null | undefined,
): "dark" | "light" {
  // Web component tokens are deliberately fixed to the audited light palette
  // until CSS-backed adaptive tokens receive their own full contrast pass.
  return platform === "web" ? "light" : preferred === "dark" ? "dark" : "light";
}
