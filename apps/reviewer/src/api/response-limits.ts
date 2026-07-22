// SPDX-License-Identifier: Apache-2.0

// Session detail deliberately duplicates each durable protocol receipt with a
// small reviewer projection. The closed V1 shape permits 2,048 segment pairs,
// 2,048 diagnostic pairs, 64 credential projections, one job summary, and one
// completion receipt. The conservative serialized budget below stays under
// 10 MiB; 16 MiB leaves schema-growth headroom while remaining a finite read
// bound. If any closed count or receipt schema changes, update this budget and
// its regression before changing the transport limit.
export const sessionDetailResponseBudget = Object.freeze({
  fixedEnvelopeBytes: 65_536,
  maximumCredentials: 64,
  credentialProjectionBytes: 512,
  maximumJobs: 1,
  jobProjectionBytes: 512,
  maximumSegments: 2_048,
  segmentProtocolReceiptBytes: 1_536,
  segmentProjectionBytes: 512,
  maximumDiagnostics: 2_048,
  diagnosticProtocolReceiptBytes: 1_536,
  diagnosticProjectionBytes: 512,
  completionReceiptBytes: 1_572_864,
} as const);

export const conservativeMaximumSessionDetailBytes =
  sessionDetailResponseBudget.fixedEnvelopeBytes
  + sessionDetailResponseBudget.maximumCredentials * sessionDetailResponseBudget.credentialProjectionBytes
  + sessionDetailResponseBudget.maximumJobs * sessionDetailResponseBudget.jobProjectionBytes
  + sessionDetailResponseBudget.maximumSegments * (
    sessionDetailResponseBudget.segmentProtocolReceiptBytes
    + sessionDetailResponseBudget.segmentProjectionBytes
  )
  + sessionDetailResponseBudget.maximumDiagnostics * (
    sessionDetailResponseBudget.diagnosticProtocolReceiptBytes
    + sessionDetailResponseBudget.diagnosticProjectionBytes
  )
  + sessionDetailResponseBudget.completionReceiptBytes;

export const maximumSessionDetailResponseBytes = 16 * 1_024 * 1_024;
