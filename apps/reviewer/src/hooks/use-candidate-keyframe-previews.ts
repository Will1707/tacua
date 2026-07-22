// SPDX-License-Identifier: Apache-2.0

import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import type { TacuaApiClient } from "@/api/client";
import type { CandidateEvidenceView, EvidencePreview, TicketCandidate } from "@/api/types";
import { collectContentEvidenceRefs } from "@/candidates/content-evidence-refs";
import {
  isKeyframeGalleryReady,
  moveKeyframeCarouselIndex,
  normalizeKeyframeCarouselIndex,
  referencedAvailableKeyframes,
  type KeyframePreviewState,
  type KeyframePreviewStates,
} from "@/candidates/keyframe-gallery-state";

const emptyPreviewStates: KeyframePreviewStates = {};
const emptyEvidenceIds: ReadonlySet<string> = new Set<string>();
const emptyErrors: Readonly<Record<string, string | undefined>> = {};

type BoundStore = {
  readonly binding: string | null;
  readonly client: TacuaApiClient | null;
};

type CarouselStore = BoundStore & { readonly index: number };
type InspectionStore = BoundStore & {
  readonly evidenceIds: ReadonlySet<string>;
  readonly errors: Readonly<Record<string, string | undefined>>;
};
type ActivePreviewStore = BoundStore & {
  readonly evidenceId: string | null;
  readonly state: KeyframePreviewState | undefined;
};
type RetainedPreview = BoundStore & {
  readonly evidenceId: string;
  readonly preview: EvidencePreview;
};

export function useCandidateKeyframePreviews(options: {
  readonly candidate: TicketCandidate | null;
  readonly client: TacuaApiClient | null;
  readonly evidence: CandidateEvidenceView | null;
}) {
  const { candidate, client, evidence } = options;
  const referencedEvidenceIds = useMemo(
    () => candidate ? collectContentEvidenceRefs(candidate.content) : [],
    [candidate],
  );
  const boundEvidence = candidate
    && evidence
    && evidence.candidate_id === candidate.candidate_id
    && evidence.candidate_version === candidate.candidate_version
    && evidence.candidate_digest === candidate.candidate_digest
    && evidence.evidence_manifest_digest === candidate.evidence_manifest.manifest_digest
      ? evidence
      : null;
  const keyframes = useMemo(
    () => referencedAvailableKeyframes(boundEvidence, referencedEvidenceIds),
    [boundEvidence, referencedEvidenceIds],
  );
  const thumbnailEvidenceIds = useMemo(() => candidate
    ? candidate.content.clarifications.flatMap((clarification) => clarification.choices.flatMap((choice) => (
        choice.presentation.kind === "evidence_thumbnail" && choice.presentation.evidence_ref
          ? [choice.presentation.evidence_ref]
          : []
      )))
    : [], [candidate]);
  const galleryBinding = candidate && boundEvidence
    ? `${candidate.candidate_id}:${candidate.candidate_version}:${candidate.candidate_digest}:${candidate.evidence_manifest.manifest_digest}`
    : null;
  const keyframeIds = useMemo(
    () => new Set(keyframes.map((item) => item.evidence_id)),
    [keyframes],
  );
  const unavailableThumbnailStates = useMemo(() => {
    const states: Record<string, KeyframePreviewState> = {};
    for (const evidenceId of thumbnailEvidenceIds) {
      if (keyframeIds.has(evidenceId) || states[evidenceId]) continue;
      const item = boundEvidence?.items.find((candidateItem) => candidateItem.evidence_id === evidenceId);
      states[evidenceId] = {
        status: "error",
        message: !item
          ? "This screenshot is not present in the candidate's bound evidence."
          : item.availability !== "available"
            ? item.unavailable?.detail ?? "This screenshot was unavailable during processing."
            : "This evidence item does not expose a supported screenshot preview.",
      };
    }
    return states;
  }, [boundEvidence?.items, keyframeIds, thumbnailEvidenceIds]);

  const [carouselStore, setCarouselStore] = useState<CarouselStore>({ binding: null, client: null, index: 0 });
  const [inspectionStore, setInspectionStore] = useState<InspectionStore>({
    binding: null,
    client: null,
    evidenceIds: emptyEvidenceIds,
    errors: emptyErrors,
  });
  const [activePreviewStore, setActivePreviewStore] = useState<ActivePreviewStore>({
    binding: null,
    client: null,
    evidenceId: null,
    state: undefined,
  });
  const [retrySequence, setRetrySequence] = useState(0);
  const retainedPreviewRef = useRef<RetainedPreview | null>(null);

  const activeIndex = carouselStore.binding === galleryBinding && carouselStore.client === client
    ? normalizeKeyframeCarouselIndex(carouselStore.index, keyframes.length)
    : 0;
  const activeKeyframe = keyframes[activeIndex] ?? null;
  const activeEvidenceId = activeKeyframe?.evidence_id ?? null;
  const decodedEvidenceIds = inspectionStore.binding === galleryBinding && inspectionStore.client === client
    ? inspectionStore.evidenceIds
    : emptyEvidenceIds;
  const retainedErrors = inspectionStore.binding === galleryBinding && inspectionStore.client === client
    ? inspectionStore.errors
    : emptyErrors;
  const activePreviewState = activePreviewStore.binding === galleryBinding
    && activePreviewStore.client === client
    && activePreviewStore.evidenceId === activeEvidenceId
      ? activePreviewStore.state
      : activeKeyframe
        ? { status: "loading" as const }
        : undefined;
  const currentGalleryRef = useRef({
    activeEvidenceId,
    activePreviewState,
    binding: galleryBinding,
    client,
    keyframeIds,
  });
  currentGalleryRef.current = {
    activeEvidenceId,
    activePreviewState,
    binding: galleryBinding,
    client,
    keyframeIds,
  };

  const releaseRetainedPreview = useCallback((expected?: {
    readonly binding: string | null;
    readonly client: TacuaApiClient | null;
    readonly evidenceId: string;
  }) => {
    const retained = retainedPreviewRef.current;
    if (!retained) return;
    if (expected && (
      retained.binding !== expected.binding
      || retained.client !== expected.client
      || retained.evidenceId !== expected.evidenceId
    )) return;
    retainedPreviewRef.current = null;
    retained.preview.release();
  }, []);

  const updateInspection = useCallback((
    evidenceId: string,
    decoded: boolean,
    errorMessage?: string,
  ) => {
    if (!galleryBinding || !keyframeIds.has(evidenceId)) return;
    setInspectionStore((current) => {
      const isCurrentBinding = current.binding === galleryBinding && current.client === client;
      const evidenceIds = new Set(isCurrentBinding ? current.evidenceIds : emptyEvidenceIds);
      const errors = { ...(isCurrentBinding ? current.errors : emptyErrors) };
      if (decoded) evidenceIds.add(evidenceId);
      else evidenceIds.delete(evidenceId);
      if (errorMessage) errors[evidenceId] = errorMessage;
      else delete errors[evidenceId];
      return { binding: galleryBinding, client, evidenceIds, errors };
    });
  }, [client, galleryBinding, keyframeIds]);

  useEffect(() => {
    let active = true;
    const evidenceId = activeKeyframe?.evidence_id ?? null;
    const expectedDigest = activeKeyframe?.preview.status === "available"
      ? activeKeyframe.preview.content_digest
      : null;
    if (!galleryBinding || !candidate || !client || !activeKeyframe || !evidenceId) {
      releaseRetainedPreview();
      setActivePreviewStore({
        binding: galleryBinding,
        client,
        evidenceId,
        state: activeKeyframe
          ? { status: "error", message: "A verified backend connection is required to inspect this screenshot." }
          : undefined,
      });
      return () => { active = false; };
    }

    const expected = { binding: galleryBinding, client, evidenceId };
    releaseRetainedPreview();
    if (!expectedDigest) {
      const message = "This available screenshot does not expose a bound preview. Approval remains locked.";
      setActivePreviewStore({ ...expected, state: { status: "error", message } });
      updateInspection(evidenceId, false, message);
      return () => { active = false; };
    }

    const controller = new AbortController();
    setActivePreviewStore({ ...expected, state: { status: "loading" } });
    setInspectionStore((current) => {
      const isCurrentBinding = current.binding === galleryBinding && current.client === client;
      const errors = { ...(isCurrentBinding ? current.errors : emptyErrors) };
      delete errors[evidenceId];
      return {
        binding: galleryBinding,
        client,
        evidenceIds: isCurrentBinding ? current.evidenceIds : emptyEvidenceIds,
        errors,
      };
    });
    void client.getEvidencePreview(candidate, evidenceId, expectedDigest, controller.signal)
      .then((preview) => {
        if (!active) {
          preview.release();
          return;
        }
        releaseRetainedPreview();
        retainedPreviewRef.current = { ...expected, preview };
        setActivePreviewStore({ ...expected, state: { status: "ready", preview } });
      })
      .catch((caught) => {
        if (!active) return;
        const message = caught instanceof Error ? caught.message : "The screenshot could not be loaded.";
        setActivePreviewStore({ ...expected, state: { status: "error", message } });
        updateInspection(evidenceId, false, message);
      });

    return () => {
      active = false;
      controller.abort();
      releaseRetainedPreview(expected);
    };
  }, [
    activeKeyframe,
    candidate,
    client,
    galleryBinding,
    releaseRetainedPreview,
    retrySequence,
    updateInspection,
  ]);

  const setKeyframeDecoded = useCallback((evidenceId: string, decoded: boolean) => {
    const currentGallery = currentGalleryRef.current;
    if (
      !currentGallery.binding
      || currentGallery.activeEvidenceId !== evidenceId
      || currentGallery.activePreviewState?.status !== "ready"
      || !currentGallery.keyframeIds.has(evidenceId)
    ) return;
    const decodeErrorMessage = "The screenshot bytes passed integrity checks but could not be decoded.";
    setInspectionStore((current) => {
      const isCurrentBinding = current.binding === currentGallery.binding
        && current.client === currentGallery.client;
      const evidenceIds = new Set(isCurrentBinding ? current.evidenceIds : emptyEvidenceIds);
      const errors = { ...(isCurrentBinding ? current.errors : emptyErrors) };
      if (decoded) {
        evidenceIds.add(evidenceId);
        delete errors[evidenceId];
      } else {
        evidenceIds.delete(evidenceId);
        errors[evidenceId] = decodeErrorMessage;
      }
      return {
        binding: currentGallery.binding,
        client: currentGallery.client,
        evidenceIds,
        errors,
      };
    });
    if (!decoded) {
      const expected = {
        binding: currentGallery.binding,
        client: currentGallery.client,
        evidenceId,
      };
      releaseRetainedPreview(expected);
      setActivePreviewStore((current) => (
        current.binding === expected.binding
        && current.client === expected.client
        && current.evidenceId === evidenceId
          ? { ...expected, state: { status: "error", message: decodeErrorMessage } }
          : current
      ));
    }
  }, [releaseRetainedPreview]);

  const move = useCallback((direction: "previous" | "next") => {
    if (!galleryBinding || !keyframes.length) return;
    setCarouselStore((current) => {
      const index = current.binding === galleryBinding && current.client === client ? current.index : 0;
      return {
        binding: galleryBinding,
        client,
        index: moveKeyframeCarouselIndex(index, keyframes.length, direction),
      };
    });
  }, [client, galleryBinding, keyframes.length]);

  const previewStates = useMemo<KeyframePreviewStates>(() => {
    if (!galleryBinding) return unavailableThumbnailStates;
    const states: Record<string, KeyframePreviewState | undefined> = { ...unavailableThumbnailStates };
    for (const item of keyframes) {
      const retainedError = retainedErrors[item.evidence_id];
      if (item.evidence_id === activeEvidenceId) {
        states[item.evidence_id] = activePreviewState;
      } else if (retainedError) {
        states[item.evidence_id] = { status: "error", message: retainedError };
      } else {
        states[item.evidence_id] = { status: "idle" };
      }
    }
    return states;
  }, [
    activeEvidenceId,
    activePreviewState,
    galleryBinding,
    keyframes,
    retainedErrors,
    unavailableThumbnailStates,
  ]);

  return {
    activeIndex,
    activePreviewState,
    inspectionReady: isKeyframeGalleryReady(keyframes, decodedEvidenceIds),
    inspectedCount: decodedEvidenceIds.size,
    keyframes,
    moveNext: () => move("next"),
    movePrevious: () => move("previous"),
    previewStates: galleryBinding ? previewStates : emptyPreviewStates,
    retryActivePreview: () => setRetrySequence((current) => current + 1),
    setKeyframeDecoded,
  } as const;
}
