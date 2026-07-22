// SPDX-License-Identifier: Apache-2.0

import { useEffect, useMemo, useState } from "react";
import { ActivityIndicator, Image, Text, View } from "react-native";

import type {
  CandidateDiagnosticEvent,
  CandidateEvidenceItem,
  CandidateEvidenceView,
} from "@/api/types";
import {
  keyframeCarouselPositionLabel,
  type KeyframePreviewState,
} from "@/candidates/keyframe-gallery-state";
import { ActionButton } from "@/components/action-button";
import { SectionCard } from "@/components/section-card";
import { colors } from "@/theme/colors";
import { formatBytes } from "@/utils/format";

type Props = {
  readonly evidence: CandidateEvidenceView | null;
  readonly activeKeyframeIndex: number;
  readonly activePreviewState: KeyframePreviewState | undefined;
  readonly inspectedKeyframeCount: number;
  readonly keyframes: readonly CandidateEvidenceItem[];
  readonly loading: boolean;
  readonly error: string | null;
  readonly retryDisabled: boolean;
  readonly onRetry: () => void;
  readonly onRetryActivePreview: () => void;
  readonly onShowNextKeyframe: () => void;
  readonly onShowPreviousKeyframe: () => void;
  readonly onKeyframeDecodeStateChange: (evidenceId: string, decoded: boolean) => void;
};

const maximumVisibleEvents = 40;

export function CandidateEvidencePanel({
  evidence,
  activeKeyframeIndex,
  activePreviewState,
  inspectedKeyframeCount,
  keyframes,
  loading,
  error,
  retryDisabled,
  onRetry,
  onRetryActivePreview,
  onShowNextKeyframe,
  onShowPreviousKeyframe,
  onKeyframeDecodeStateChange,
}: Props) {
  const events = useMemo(
    () => [...(evidence?.diagnostic_events ?? [])].sort((left, right) => left.elapsed_ms - right.elapsed_ms).slice(0, maximumVisibleEvents),
    [evidence?.diagnostic_events],
  );

  return (
    <SectionCard
      title="Evidence from this run"
      trailing={evidence ? <Text style={{ color: colors.tertiaryLabel }}>{evidence.items.length} items</Text> : undefined}
    >
      {loading ? (
        <View accessible accessibilityLabel="Loading ticket evidence" accessibilityRole="progressbar" style={{ minHeight: 96, alignItems: "center", justifyContent: "center" }}>
          <ActivityIndicator color={colors.primary} />
        </View>
      ) : error ? (
        <View style={{ gap: 4 }}>
          <Text selectable accessibilityRole="alert" style={{ color: colors.orange, fontWeight: "700" }}>Evidence is temporarily unavailable</Text>
          <Text selectable style={{ color: colors.secondaryLabel }}>{error}</Text>
          <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>The ticket remains visible, but do not approve it until its bound evidence can be inspected.</Text>
          <ActionButton disabled={retryDisabled} label="Retry evidence check" onPress={onRetry} />
        </View>
      ) : evidence ? (
        <View style={{ gap: 16 }}>
          <KeyframeGallery
            activeIndex={activeKeyframeIndex}
            items={keyframes}
            inspectedCount={inspectedKeyframeCount}
            previewState={activePreviewState}
            onKeyframeDecodeStateChange={onKeyframeDecodeStateChange}
            onNext={onShowNextKeyframe}
            onPrevious={onShowPreviousKeyframe}
            onRetry={onRetryActivePreview}
          />

          <View style={{ gap: 8 }}>
            <Text selectable style={{ color: colors.label, fontWeight: "800", fontSize: 15 }}>SDK timeline</Text>
            {events.length ? events.map((event) => <DiagnosticEventRow event={event} key={event.event_id} />) : (
              <Text selectable style={{ color: colors.secondaryLabel }}>No candidate-scoped SDK events were retained.</Text>
            )}
            {(evidence.diagnostic_events.length > maximumVisibleEvents) ? (
              <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>
                Showing the first {maximumVisibleEvents} of {evidence.diagnostic_events.length} bound events.
              </Text>
            ) : null}
          </View>

          <View style={{ gap: 8 }}>
            <Text selectable style={{ color: colors.label, fontWeight: "800", fontSize: 15 }}>Evidence sources</Text>
            {evidence.items.map((item) => <EvidenceSourceRow item={item} key={item.evidence_id} />)}
          </View>
        </View>
      ) : (
        <Text selectable style={{ color: colors.secondaryLabel }}>No evidence manifest is available for this candidate.</Text>
      )}
    </SectionCard>
  );
}

function KeyframeGallery({
  activeIndex,
  items,
  inspectedCount,
  previewState,
  onKeyframeDecodeStateChange,
  onNext,
  onPrevious,
  onRetry,
}: {
  readonly activeIndex: number;
  readonly items: readonly CandidateEvidenceItem[];
  readonly inspectedCount: number;
  readonly previewState: KeyframePreviewState | undefined;
  readonly onKeyframeDecodeStateChange: (evidenceId: string, decoded: boolean) => void;
  readonly onNext: () => void;
  readonly onPrevious: () => void;
  readonly onRetry: () => void;
}) {
  if (!items.length) {
    return (
      <View style={{ minHeight: 112, borderRadius: 14, borderCurve: "continuous", backgroundColor: colors.groupedBackground, alignItems: "center", justifyContent: "center", padding: 16 }}>
        <Text selectable style={{ color: colors.secondaryLabel, textAlign: "center" }}>No available screenshot was referenced anywhere in this ticket. Approval remains locked.</Text>
      </View>
    );
  }

  const item = items[activeIndex] ?? items[0];
  if (!item) return null;
  const positionLabel = keyframeCarouselPositionLabel(activeIndex, items.length);

  return (
    <View style={{ gap: 12 }}>
      <View style={{ flexDirection: "row", flexWrap: "wrap", justifyContent: "space-between", alignItems: "baseline", gap: 8 }}>
        <Text selectable style={{ color: colors.label, fontWeight: "800", fontSize: 15, flexShrink: 1 }}>Referenced screenshot gallery</Text>
        <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12, fontVariant: ["tabular-nums"] }}>
          {Math.min(inspectedCount, items.length)} of {items.length} inspected
        </Text>
      </View>
      <Text
        accessibilityLiveRegion="polite"
        selectable
        style={{ color: colors.tertiaryLabel, fontSize: 12, fontWeight: "700", textTransform: "uppercase", fontVariant: ["tabular-nums"] }}
      >
        {positionLabel}
      </Text>
      <KeyframePreview
        item={item}
        key={`${item.evidence_id}:${item.preview.content_digest ?? "missing-preview"}`}
        position={activeIndex + 1}
        previewState={previewState}
        total={items.length}
        onDecodeStateChange={onKeyframeDecodeStateChange}
        onRetry={onRetry}
      />
      <View style={{ flexDirection: "row", gap: 10 }}>
        <View style={{ flex: 1 }}>
          <ActionButton disabled={activeIndex <= 0} label="Previous screenshot" onPress={onPrevious} />
        </View>
        <View style={{ flex: 1 }}>
          <ActionButton disabled={activeIndex >= items.length - 1} label="Next screenshot" onPress={onNext} />
        </View>
      </View>
    </View>
  );
}

function KeyframePreview({
  item,
  position,
  previewState,
  total,
  onDecodeStateChange,
  onRetry,
}: {
  readonly item: CandidateEvidenceItem;
  readonly position: number;
  readonly previewState: KeyframePreviewState | undefined;
  readonly total: number;
  readonly onDecodeStateChange: (evidenceId: string, decoded: boolean) => void;
  readonly onRetry: () => void;
}) {
  const [decodeError, setDecodeError] = useState<string | null>(null);
  useEffect(() => {
    // A newly fetched, re-bound preview deserves a fresh native decode attempt.
    // Do not let a prior transient Image failure permanently poison this row.
    setDecodeError(null);
  }, [item.evidence_id, item.preview.content_digest, previewState]);

  return (
    <View style={{ gap: 8 }}>
      {decodeError || previewState?.status === "error" ? (
        <View style={{ minHeight: 112, borderRadius: 14, borderCurve: "continuous", backgroundColor: colors.groupedBackground, alignItems: "center", justifyContent: "center", padding: 16, gap: 4 }}>
          <Text selectable accessibilityRole="alert" style={{ color: colors.orange, fontWeight: "700" }}>Screenshot unavailable</Text>
          <Text selectable style={{ color: colors.secondaryLabel, textAlign: "center" }}>
            {decodeError ?? (previewState?.status === "error" ? previewState.message : "The screenshot could not be loaded.")}
          </Text>
          <ActionButton
            label={`Retry screenshot ${position}`}
            onPress={() => {
              setDecodeError(null);
              onRetry();
            }}
          />
        </View>
      ) : previewState?.status !== "ready" ? (
        <View accessible accessibilityLabel={`Loading bound screenshot ${position} of ${total}`} accessibilityRole="progressbar" style={{ minHeight: 240, borderRadius: 14, borderCurve: "continuous", backgroundColor: colors.groupedBackground, alignItems: "center", justifyContent: "center" }}>
          <ActivityIndicator color={colors.primary} />
        </View>
      ) : (
        <View style={{ overflow: "hidden", borderRadius: 14, borderCurve: "continuous", borderColor: colors.separator, borderWidth: 1, backgroundColor: colors.groupedBackground }}>
          <Image
            accessible
            accessibilityLabel={`${item.description}. Screenshot ${position} of ${total}.`}
            onError={() => {
              setDecodeError("The screenshot bytes passed integrity checks but could not be decoded.");
              onDecodeStateChange(item.evidence_id, false);
            }}
            onLoad={() => onDecodeStateChange(item.evidence_id, true)}
            resizeMode="contain"
            source={{ uri: previewState.preview.uri }}
            style={{ width: "100%", aspectRatio: 9 / 16, maxHeight: 560 }}
          />
        </View>
      )}
      <Text selectable style={{ color: colors.label, lineHeight: 20 }}>{item.description}</Text>
      <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>
        {formatElapsed(item.time_range?.start_ms)}
        {previewState?.status === "ready"
          ? ` · ${formatBytes(previewState.preview.sizeBytes)} · digest verified`
          : previewState?.status === "error"
            ? " · verification failed"
            : " · verification pending"}
      </Text>
    </View>
  );
}

function DiagnosticEventRow({ event }: { readonly event: CandidateDiagnosticEvent }) {
  const summary = diagnosticSummary(event);
  const warning = event.event_type === "runtime_error" || event.event_type === "capture_gap"
    || (event.event_type === "network_request_completed" && event.data.outcome !== "success");
  return (
    <View style={{ flexDirection: "row", gap: 10, alignItems: "flex-start" }}>
      <View
        accessibilityElementsHidden
        importantForAccessibility="no-hide-descendants"
        style={{ marginTop: 6, width: 8, height: 8, borderRadius: 4, backgroundColor: warning ? colors.orange : colors.primary }}
      />
      <View style={{ flex: 1, gap: 2 }}>
        <Text selectable style={{ color: colors.label, lineHeight: 20 }}>{summary.title}</Text>
        {summary.detail ? <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 19 }}>{summary.detail}</Text> : null}
        <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>{formatElapsed(event.elapsed_ms)} · {event.source.replace("_", " ")}</Text>
      </View>
    </View>
  );
}

function EvidenceSourceRow({ item }: { readonly item: CandidateEvidenceItem }) {
  const unavailable = item.availability === "unavailable";
  return (
    <View style={{ borderTopColor: colors.separator, borderTopWidth: 1, paddingTop: 8, gap: 2 }}>
      <Text selectable style={{ color: unavailable ? colors.orange : colors.label, fontWeight: "700" }}>
        {humanize(item.evidence_type)}
      </Text>
      <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 19 }}>{item.description}</Text>
      <Text selectable style={{ color: colors.tertiaryLabel, fontSize: 12 }}>
        {item.source.component.replace("_", " ")}{item.time_range ? ` · ${formatElapsed(item.time_range.start_ms)}` : ""}
      </Text>
      {item.unavailable ? <Text selectable style={{ color: colors.orange, fontSize: 12 }}>{item.unavailable.detail}</Text> : null}
    </View>
  );
}

function diagnosticSummary(event: CandidateDiagnosticEvent): { readonly title: string; readonly detail: string | null } {
  switch (event.event_type) {
    case "route_transition":
      return { title: `${event.data.from_route ?? "App launch"} → ${event.data.to_route}`, detail: `${humanize(event.data.trigger)} navigation` };
    case "user_interaction":
      return { title: `${humanize(event.data.action)} · ${event.data.target}`, detail: "Input values were not collected." };
    case "runtime_error":
      return { title: event.data.error_class, detail: `${event.data.sanitized_message}${event.data.handled ? " · handled" : " · unhandled"}` };
    case "network_request_completed": {
      const status = event.data.status_code === null ? event.data.outcome : String(event.data.status_code);
      const duration = event.data.duration_ms === null ? "duration unavailable" : `${event.data.duration_ms} ms`;
      return { title: `${event.data.method} ${event.data.host}${event.data.path_template}`, detail: `${status} · ${duration} · bodies not collected` };
    }
    case "app_state_changed":
      return { title: `${humanize(event.data.from_state)} → ${humanize(event.data.to_state)}`, detail: "App state changed" };
    case "issue_mark":
      return { title: `${humanize(event.data.kind)} issue mark`, detail: `Narration at ${formatElapsed(event.data.narration_elapsed_ms)}` };
    case "capture_gap":
      return { title: "Capture gap", detail: event.data.affected_streams.map(humanize).join(", ") };
    case "custom_state":
      return { title: `State provider · ${event.data.provider_id}`, detail: humanize(event.data.collection_status) };
  }
}

function humanize(value: string): string {
  return value.replace(/[._]/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function formatElapsed(milliseconds: number | undefined): string {
  if (milliseconds === undefined || !Number.isFinite(milliseconds) || milliseconds < 0) return "Time unavailable";
  const minutes = Math.floor(milliseconds / 60_000);
  const seconds = Math.floor((milliseconds % 60_000) / 1_000);
  return `${minutes}:${String(seconds).padStart(2, "0")}`;
}
