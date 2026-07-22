// SPDX-License-Identifier: Apache-2.0

import { useEffect, useState } from "react";
import { Pressable, Text, TextInput, View } from "react-native";

import type { TicketCandidate } from "@/api/types";
import { ActionButton } from "@/components/action-button";
import { SectionCard } from "@/components/section-card";
import { colors } from "@/theme/colors";

type EditableContent = TicketCandidate["content"];
type Priority = EditableContent["priority"];

type Props = {
  readonly candidate: TicketCandidate;
  readonly disabled: boolean;
  readonly saving: boolean;
  readonly onSave: (content: EditableContent) => Promise<boolean>;
};

function normalized(value: string, label: string, maximum: number): string {
  const result = value.trim().normalize("NFC");
  const length = Array.from(result).length;
  if (length < 1 || length > maximum || /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(result)) {
    throw new Error(`${label} must contain 1–${maximum} safe characters.`);
  }
  return result;
}

export function CandidateEditCard({ candidate, disabled, saving, onSave }: Props) {
  const [editing, setEditing] = useState(false);
  const [title, setTitle] = useState(candidate.content.title);
  const [priority, setPriority] = useState<Priority>(candidate.content.priority);
  const [summary, setSummary] = useState(candidate.content.summary.text);
  const [actual, setActual] = useState(candidate.content.actual_behavior.text);
  const [expected, setExpected] = useState(candidate.content.expected_behavior.text);
  const [error, setError] = useState<string | null>(null);
  const binding = `${candidate.candidate_id}:${candidate.candidate_version}:${candidate.candidate_digest}`;

  useEffect(() => {
    setEditing(false);
    setTitle(candidate.content.title);
    setPriority(candidate.content.priority);
    setSummary(candidate.content.summary.text);
    setActual(candidate.content.actual_behavior.text);
    setExpected(candidate.content.expected_behavior.text);
    setError(null);
  }, [binding, candidate]);

  const editable = ["draft", "needs_clarification", "ready_for_review"].includes(candidate.state);
  if (!editable) return null;

  async function save() {
    setError(null);
    try {
      const content: EditableContent = {
        ...candidate.content,
        title: normalized(title, "Title", 256),
        priority,
        summary: {
          ...candidate.content.summary,
          text: normalized(summary, "Summary", 4_096),
        },
        actual_behavior: {
          ...candidate.content.actual_behavior,
          text: normalized(actual, "Actual behaviour", 4_096),
        },
        expected_behavior: {
          ...candidate.content.expected_behavior,
          text: normalized(expected, "Expected behaviour", 4_096),
        },
      };
      if (JSON.stringify(content) === JSON.stringify(candidate.content)) {
        throw new Error("Change at least one field before saving.");
      }
      if (await onSave(content)) setEditing(false);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The edited ticket is invalid.");
    }
  }

  if (!editing) {
    return (
      <SectionCard title="Edit ticket">
        <Text selectable style={{ color: colors.secondaryLabel, lineHeight: 20 }}>
          Correct the agent-facing title, priority, summary, actual behaviour, or expected behaviour.
          Evidence links and reproduction details remain attached to this immutable version chain.
        </Text>
        <ActionButton label="Edit candidate" disabled={disabled} onPress={() => setEditing(true)} />
      </SectionCard>
    );
  }

  const inputStyle = {
    color: colors.label,
    backgroundColor: colors.groupedBackground,
    borderColor: colors.separator,
    borderWidth: 1,
    borderRadius: 12,
    borderCurve: "continuous" as const,
    minHeight: 44,
    paddingHorizontal: 12,
    paddingVertical: 10,
    fontSize: 16,
  };
  return (
    <SectionCard title="Edit ticket">
      <Text selectable style={{ color: colors.secondaryLabel, fontSize: 13 }}>
        Saving creates a new draft version. You will review that exact version again before approval.
      </Text>
      <Text style={{ color: colors.label, fontWeight: "700" }}>Title</Text>
      <TextInput accessibilityLabel="Ticket title" value={title} onChangeText={setTitle} maxLength={256} style={inputStyle} />
      <Text style={{ color: colors.label, fontWeight: "700" }}>Priority</Text>
      <View accessibilityRole="radiogroup" style={{ flexDirection: "row", gap: 8 }}>
        {(["P0", "P1", "P2", "P3"] as const).map((value) => (
          <Pressable
            key={value}
            accessibilityRole="radio"
            accessibilityState={{ checked: priority === value }}
            onPress={() => setPriority(value)}
            style={{
              minHeight: 44,
              minWidth: 48,
              alignItems: "center",
              justifyContent: "center",
              borderRadius: 12,
              borderCurve: "continuous",
              borderWidth: 1,
              borderColor: priority === value ? colors.primary : colors.separator,
              backgroundColor: priority === value ? colors.primary : colors.groupedBackground,
            }}
          >
            <Text style={{ color: priority === value ? colors.onPrimary : colors.label, fontWeight: "800" }}>{value}</Text>
          </Pressable>
        ))}
      </View>
      {([
        ["Summary", summary, setSummary],
        ["Actual behaviour", actual, setActual],
        ["Expected behaviour", expected, setExpected],
      ] as const).map(([label, value, setter]) => (
        <View key={label} style={{ gap: 7 }}>
          <Text style={{ color: colors.label, fontWeight: "700" }}>{label}</Text>
          <TextInput
            accessibilityLabel={label}
            multiline
            value={value}
            onChangeText={setter}
            maxLength={4_096}
            style={{ ...inputStyle, minHeight: 96, textAlignVertical: "top" }}
          />
        </View>
      ))}
      {error ? <Text selectable style={{ color: colors.orange, lineHeight: 20 }}>{error}</Text> : null}
      <ActionButton label="Save new draft version" disabled={disabled} loading={saving} onPress={() => void save()} />
      <Pressable accessibilityRole="button" disabled={saving} onPress={() => { setEditing(false); setError(null); }} style={{ minHeight: 44, justifyContent: "center", alignItems: "center" }}>
        <Text style={{ color: colors.primary, fontWeight: "800" }}>Cancel editing</Text>
      </Pressable>
    </SectionCard>
  );
}
