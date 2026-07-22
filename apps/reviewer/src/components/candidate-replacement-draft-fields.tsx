// SPDX-License-Identifier: Apache-2.0

import type { ReactNode } from "react";
import { Pressable, Text, TextInput, View } from "react-native";

import type { CandidateReplacementDraft, TicketCandidate } from "@/api/types";
import { colors } from "@/theme/colors";

type Priority = TicketCandidate["content"]["priority"];
type CandidateContent = TicketCandidate["content"];

type Props = {
  readonly draft: CandidateReplacementDraft;
  readonly index: number;
  readonly disabled: boolean;
  readonly canRemove: boolean;
  readonly onChange: (draft: CandidateReplacementDraft) => void;
  readonly onRemove: () => void;
};

function displayScalar(value: string | number | boolean | null): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  return String(value);
}

function ExactField({ label, value }: {
  readonly label: string;
  readonly value: string | number | boolean | null;
}) {
  return (
    <View style={{ gap: 3 }}>
      <Text style={{ color: colors.tertiaryLabel, fontSize: 12, fontWeight: "700" }}>{label}</Text>
      <Text selectable style={{ color: colors.label }}>{displayScalar(value)}</Text>
    </View>
  );
}

function ExactList({ label, values }: {
  readonly label: string;
  readonly values: readonly string[];
}) {
  return (
    <View style={{ gap: 3 }}>
      <Text style={{ color: colors.tertiaryLabel, fontSize: 12, fontWeight: "700" }}>{label}</Text>
      {values.length ? values.map((value, index) => (
        <Text selectable key={`${label}:${index}`} style={{ color: colors.label }}>
          {index + 1}. {value}
        </Text>
      )) : <Text selectable style={{ color: colors.secondaryLabel }}>None</Text>}
    </View>
  );
}

function ReadOnlyGroup({ title, children }: { readonly title: string; readonly children: ReactNode }) {
  return (
    <View style={{ backgroundColor: colors.secondaryBackground, borderColor: colors.separator, borderWidth: 1, borderRadius: 12, borderCurve: "continuous", padding: 12, gap: 10 }}>
      <Text selectable accessibilityRole="header" style={{ color: colors.label, fontSize: 16, fontWeight: "800" }}>{title}</Text>
      {children}
    </View>
  );
}

function ExactItem({ title, children }: { readonly title: string; readonly children: ReactNode }) {
  return (
    <View style={{ borderTopColor: colors.separator, borderTopWidth: 1, paddingTop: 10, gap: 8 }}>
      <Text selectable accessibilityRole="header" style={{ color: colors.label, fontWeight: "800" }}>{title}</Text>
      {children}
    </View>
  );
}

function GroundingFields({ label, value }: {
  readonly label: string;
  readonly value: CandidateContent["summary"];
}) {
  return (
    <ExactItem title={label}>
      <ExactList label="Claim references" values={value.claim_refs} />
      <ExactList label="Evidence references" values={value.evidence_refs} />
    </ExactItem>
  );
}

function CandidateReplacementContentReview({ content, index }: {
  readonly content: CandidateContent;
  readonly index: number;
}) {
  return (
    <View style={{ gap: 10 }}>
      <View style={{ gap: 4, paddingTop: 4 }}>
        <Text selectable accessibilityRole="header" style={{ color: colors.label, fontSize: 17, fontWeight: "800" }}>
          Complete result content
        </Text>
        <Text selectable style={{ color: colors.secondaryLabel }}>
          The five fields above are editable. Every remaining field in result draft {index + 1} is shown below read-only and will be submitted exactly as displayed.
        </Text>
      </View>

      <ReadOnlyGroup title="Grounding for editable text">
        <GroundingFields label="Summary grounding" value={content.summary} />
        <GroundingFields label="Actual behaviour grounding" value={content.actual_behavior} />
        <GroundingFields label="Expected behaviour grounding" value={content.expected_behavior} />
      </ReadOnlyGroup>

      <ReadOnlyGroup title="Claims and grounding">
        {content.claims.map((claim, claimIndex) => (
          <ExactItem key={claim.claim_id} title={`Claim ${claimIndex + 1}`}>
            <ExactField label="Claim ID" value={claim.claim_id} />
            <ExactField label="Kind" value={claim.kind} />
            <ExactField label="Support" value={claim.support} />
            <ExactField label="Confidence" value={claim.confidence} />
            <ExactField label="Statement" value={claim.statement} />
            <ExactList label="Evidence references" values={claim.evidence_refs} />
          </ExactItem>
        ))}
      </ReadOnlyGroup>

      <ReadOnlyGroup title="Reproduction details">
        <ExactField label="Attempts" value={content.reproduction.attempts} />
        <ExactField label="Reproductions" value={content.reproduction.reproductions} />
        <Text selectable accessibilityRole="header" style={{ color: colors.label, fontWeight: "800" }}>Preconditions</Text>
        {content.reproduction.preconditions.length ? content.reproduction.preconditions.map((precondition, preconditionIndex) => (
          <ExactItem key={precondition.precondition_id} title={`Precondition ${preconditionIndex + 1}`}>
            <ExactField label="Precondition ID" value={precondition.precondition_id} />
            <ExactField label="Text" value={precondition.text} />
            <ExactList label="Claim references" values={precondition.claim_refs} />
            <ExactList label="Evidence references" values={precondition.evidence_refs} />
          </ExactItem>
        )) : <Text selectable style={{ color: colors.secondaryLabel }}>None</Text>}
        <Text selectable accessibilityRole="header" style={{ color: colors.label, fontWeight: "800" }}>Steps</Text>
        {content.reproduction.steps.map((step, stepIndex) => (
          <ExactItem key={step.step_id} title={`Step ${stepIndex + 1}`}>
            <ExactField label="Step ID" value={step.step_id} />
            <ExactField label="Action" value={step.action} />
            <ExactField label="Expected result" value={step.expected_result} />
            <ExactField label="Actual result" value={step.actual_result} />
            <ExactField label="Confidence" value={step.confidence} />
            <ExactList label="Claim references" values={step.claim_refs} />
            <ExactList label="Evidence references" values={step.evidence_refs} />
          </ExactItem>
        ))}
      </ReadOnlyGroup>

      <ReadOnlyGroup title="Scope">
        <ExactList label="In scope" values={content.scope.in_scope} />
        <ExactList label="Out of scope" values={content.scope.out_of_scope} />
      </ReadOnlyGroup>

      <ReadOnlyGroup title="Acceptance criteria">
        {content.acceptance_criteria.map((criterion, criterionIndex) => (
          <ExactItem key={criterion.criterion_id} title={`Criterion ${criterionIndex + 1}`}>
            <ExactField label="Criterion ID" value={criterion.criterion_id} />
            <ExactField label="Criterion" value={criterion.criterion} />
            <ExactField label="Verification" value={criterion.verification} />
            <ExactList label="Claim references" values={criterion.claim_refs} />
            <ExactList label="Evidence references" values={criterion.evidence_refs} />
          </ExactItem>
        ))}
      </ReadOnlyGroup>

      <ReadOnlyGroup title="Uncertainty">
        <ExactField label="Overall confidence" value={content.uncertainty.overall_confidence} />
        {content.uncertainty.items.length ? content.uncertainty.items.map((item, itemIndex) => (
          <ExactItem key={item.uncertainty_id} title={`Uncertainty ${itemIndex + 1}`}>
            <ExactField label="Uncertainty ID" value={item.uncertainty_id} />
            <ExactField label="Statement" value={item.statement} />
            <ExactField label="Impact" value={item.impact} />
            <ExactList label="Evidence references" values={item.evidence_refs} />
          </ExactItem>
        )) : <Text selectable style={{ color: colors.secondaryLabel }}>No uncertainty items</Text>}
      </ReadOnlyGroup>

      <ReadOnlyGroup title="Clarifications">
        {content.clarifications.length ? content.clarifications.map((clarification, clarificationIndex) => (
          <ExactItem key={clarification.clarification_id} title={`Clarification ${clarificationIndex + 1}`}>
            <ExactField label="Clarification ID" value={clarification.clarification_id} />
            <ExactField label="Question" value={clarification.question} />
            <ExactField label="Target" value={clarification.target} />
            <ExactField label="Impact" value={clarification.impact} />
            <ExactField label="Status" value={clarification.status} />
            <ExactField label="Selected choice ID" value={clarification.selected_choice_id} />
            <ExactField label="Resolution note" value={clarification.resolution_note} />
            <Text selectable accessibilityRole="header" style={{ color: colors.label, fontWeight: "800" }}>Choices</Text>
            {clarification.choices.map((choice, choiceIndex) => (
              <ExactItem key={choice.choice_id} title={`Choice ${choiceIndex + 1}`}>
                <ExactField label="Choice ID" value={choice.choice_id} />
                <ExactField label="Label" value={choice.label} />
                <ExactField label="Description" value={choice.description} />
                <ExactField label="Consequence" value={choice.consequence} />
                <ExactField label="Requires note" value={choice.requires_note} />
                <ExactField label="Presentation kind" value={choice.presentation.kind} />
                <ExactField label="Presentation value" value={choice.presentation.value} />
                <ExactField label="Presentation evidence reference" value={choice.presentation.evidence_ref} />
                <ExactList label="Evidence references" values={choice.evidence_refs} />
              </ExactItem>
            ))}
          </ExactItem>
        )) : <Text selectable style={{ color: colors.secondaryLabel }}>No clarifications</Text>}
      </ReadOnlyGroup>
    </View>
  );
}

export function CandidateReplacementDraftFields({
  draft,
  index,
  disabled,
  canRemove,
  onChange,
  onRemove,
}: Props) {
  const updateContent = (update: Partial<TicketCandidate["content"]>) => {
    onChange({ ...draft, content: { ...draft.content, ...update } });
  };
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
    <View style={{ borderTopColor: colors.separator, borderTopWidth: 1, paddingTop: 12, gap: 9 }}>
      <View style={{ flexDirection: "row", justifyContent: "space-between", alignItems: "center", gap: 12 }}>
        <Text selectable style={{ color: colors.label, fontSize: 16, fontWeight: "800", flex: 1 }}>Result draft {index + 1}</Text>
        {canRemove ? (
          <Pressable
            accessibilityLabel={`Remove result draft ${index + 1}`}
            accessibilityRole="button"
            disabled={disabled}
            onPress={onRemove}
            style={{ minHeight: 44, minWidth: 44, justifyContent: "center", alignItems: "flex-end" }}
          >
            <Text style={{ color: colors.red, fontWeight: "700" }}>Remove</Text>
          </Pressable>
        ) : null}
      </View>
      <Text style={{ color: colors.label, fontWeight: "700" }}>Title</Text>
      <TextInput
        accessibilityLabel={`Result draft ${index + 1} title`}
        editable={!disabled}
        maxLength={256}
        value={draft.content.title}
        onChangeText={(title) => updateContent({ title })}
        style={inputStyle}
      />
      <Text style={{ color: colors.label, fontWeight: "700" }}>Priority</Text>
      <View accessibilityRole="radiogroup" style={{ flexDirection: "row", flexWrap: "wrap", gap: 8 }}>
        {(["P0", "P1", "P2", "P3"] as const).map((priority: Priority) => (
          <Pressable
            key={priority}
            accessibilityLabel={`Result draft ${index + 1} priority ${priority}`}
            accessibilityRole="radio"
            accessibilityState={{ checked: draft.content.priority === priority, disabled }}
            disabled={disabled}
            onPress={() => updateContent({ priority })}
            style={{
              minHeight: 44,
              minWidth: 48,
              alignItems: "center",
              justifyContent: "center",
              borderRadius: 12,
              borderCurve: "continuous",
              borderWidth: 1,
              borderColor: draft.content.priority === priority ? colors.primary : colors.separator,
              backgroundColor: draft.content.priority === priority ? colors.primary : colors.groupedBackground,
            }}
          >
            <Text style={{ color: draft.content.priority === priority ? colors.onPrimary : colors.label, fontWeight: "800" }}>{priority}</Text>
          </Pressable>
        ))}
      </View>
      {([
        ["Summary", draft.content.summary.text, (text: string) => updateContent({ summary: { ...draft.content.summary, text } })],
        ["Actual behaviour", draft.content.actual_behavior.text, (text: string) => updateContent({ actual_behavior: { ...draft.content.actual_behavior, text } })],
        ["Expected behaviour", draft.content.expected_behavior.text, (text: string) => updateContent({ expected_behavior: { ...draft.content.expected_behavior, text } })],
      ] as const).map(([label, value, onChangeText]) => (
        <View key={label} style={{ gap: 7 }}>
          <Text style={{ color: colors.label, fontWeight: "700" }}>{label}</Text>
          <TextInput
            accessibilityLabel={`Result draft ${index + 1} ${label.toLocaleLowerCase("en-US")}`}
            editable={!disabled}
            maxLength={4_096}
            multiline
            value={value}
            onChangeText={onChangeText}
            style={{ ...inputStyle, minHeight: 96, textAlignVertical: "top" }}
          />
        </View>
      ))}
      <CandidateReplacementContentReview content={draft.content} index={index} />
      <ExactField label="Result candidate ID" value={draft.candidate_id} />
    </View>
  );
}
