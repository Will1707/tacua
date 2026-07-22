// SPDX-License-Identifier: Apache-2.0

import type { CandidateEvidenceItem, CandidateEvidenceView, EvidencePreview } from "@/api/types";

export type KeyframePreviewState =
  | { readonly status: "idle" }
  | { readonly status: "loading" }
  | { readonly status: "ready"; readonly preview: EvidencePreview }
  | { readonly status: "error"; readonly message: string };

export type KeyframePreviewStates = Readonly<Record<string, KeyframePreviewState | undefined>>;

export function referencedAvailableKeyframes(
  evidence: CandidateEvidenceView | null,
  referencedEvidenceIds: readonly string[],
): readonly CandidateEvidenceItem[] {
  if (!evidence) return [];
  const itemsById = new Map(evidence.items.map((item) => [item.evidence_id, item]));
  return referencedEvidenceIds.flatMap((evidenceId) => {
    const item = itemsById.get(evidenceId);
    return item?.evidence_type === "media.keyframe" && item.availability === "available"
      ? [item]
      : [];
  });
}

export function isKeyframeGalleryReady(
  keyframes: readonly CandidateEvidenceItem[],
  decodedEvidenceIds: ReadonlySet<string>,
): boolean {
  return keyframes.length > 0 && keyframes.every((item) => decodedEvidenceIds.has(item.evidence_id));
}

export function normalizeKeyframeCarouselIndex(index: number, itemCount: number): number {
  if (!Number.isSafeInteger(index) || !Number.isSafeInteger(itemCount) || itemCount <= 0) return 0;
  return Math.min(Math.max(index, 0), itemCount - 1);
}

export function moveKeyframeCarouselIndex(
  index: number,
  itemCount: number,
  direction: "previous" | "next",
): number {
  const current = normalizeKeyframeCarouselIndex(index, itemCount);
  return normalizeKeyframeCarouselIndex(current + (direction === "previous" ? -1 : 1), itemCount);
}

export function keyframeCarouselPositionLabel(index: number, itemCount: number): string {
  if (!Number.isSafeInteger(itemCount) || itemCount <= 0) return "No screenshots";
  return `Screenshot ${normalizeKeyframeCarouselIndex(index, itemCount) + 1} of ${itemCount}`;
}
