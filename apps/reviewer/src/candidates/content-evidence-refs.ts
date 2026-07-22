// SPDX-License-Identifier: Apache-2.0

import type { TicketCandidate } from "@/api/types";

/**
 * Collect every evidence reference that is part of ticket content.
 *
 * This intentionally mirrors the ticket-candidate contract's recursive
 * `content_evidence_refs` walk. Keeping the reviewer exhaustive prevents its
 * approval gate from disagreeing with the backend when evidence is cited by a
 * reproduction step, acceptance criterion, uncertainty, or clarification.
 */
export function collectContentEvidenceRefs(
  content: TicketCandidate["content"],
): readonly string[] {
  const refs = new Set<string>();
  const visited = new WeakSet<object>();

  function visit(value: unknown): void {
    if (typeof value !== "object" || value === null) return;
    if (visited.has(value)) return;
    visited.add(value);

    if (Array.isArray(value)) {
      value.forEach(visit);
      return;
    }

    const record = value as Record<string, unknown>;
    if (Array.isArray(record.evidence_refs)) {
      for (const evidenceRef of record.evidence_refs) {
        if (typeof evidenceRef === "string") refs.add(evidenceRef);
      }
    }

    const presentation = record.presentation;
    if (typeof presentation === "object" && presentation !== null && !Array.isArray(presentation)) {
      const evidenceRef = (presentation as Record<string, unknown>).evidence_ref;
      if (typeof evidenceRef === "string") refs.add(evidenceRef);
    }

    Object.values(record).forEach(visit);
  }

  visit(content);
  return [...refs];
}
