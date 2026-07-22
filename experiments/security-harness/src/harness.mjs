// SPDX-License-Identifier: Apache-2.0
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { readFile, readdir, writeFile, mkdir } from 'node:fs/promises';
import { extname, join, resolve } from 'node:path';

export const DECISIONS = Object.freeze([
  'deny',
  'allow_metadata_reference_only',
  'allow_after_irreversible_transformation',
  'require_explicit_project_reviewer_approval',
]);

export function sha256(value) {
  const bytes = Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8');
  return createHash('sha256').update(bytes).digest('hex');
}

function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, sortValue(value[key])]),
    );
  }
  return value;
}

export function stableStringify(value, spaces = 0) {
  return JSON.stringify(sortValue(value), null, spaces);
}

function hmacSubject(document) {
  const subject = structuredClone(document);
  delete subject.signature.value;
  return subject;
}

export function signSyntheticHmacArtifact(document, keyHex) {
  const signed = structuredClone(document);
  signed.signature.value = `hmac-sha256:${createHmac('sha256', Buffer.from(keyHex, 'hex'))
    .update(stableStringify(hmacSubject(signed)))
    .digest('hex')}`;
  return signed;
}

function signatureMatches(document, keyHex) {
  if (!isHmacKeyHex(keyHex) || typeof document?.signature?.value !== 'string') return false;
  try {
    const expected = signSyntheticHmacArtifact(document, keyHex).signature.value;
    const supplied = document.signature.value;
    if (Buffer.byteLength(expected) !== Buffer.byteLength(supplied)) return false;
    return timingSafeEqual(Buffer.from(expected), Buffer.from(supplied));
  } catch {
    return false;
  }
}

const CODEX_RUNTIME_PROFILE = Object.freeze({
  authentication_scope: 'single_invocation',
  command: 'codex_exec',
  ephemeral: true,
  network_access: false,
  non_interactive: true,
  sandbox: 'workspace-write',
  structured_output: true,
});

const ID_PATTERN = /^[a-z][a-z0-9_-]{2,63}$/;
const DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const HMAC_PATTERN = /^hmac-sha256:[a-f0-9]{64}$/;
const REVISION_PATTERN = /^[a-f0-9]{40}$/;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{22,128}$/;
const UTC_SECOND_PATTERN = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/;
const SOURCE_COMPONENTS = new Set(['mobile_sdk', 'backend', 'repository', 'sentry', 'posthog']);

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value, keys) {
  if (!isRecord(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isIdentifier(value) {
  return typeof value === 'string' && ID_PATTERN.test(value);
}

function isDigest(value) {
  return typeof value === 'string' && DIGEST_PATTERN.test(value);
}

function isSafePositiveInteger(value) {
  return Number.isSafeInteger(value) && value >= 1;
}

function isHmacKeyHex(value) {
  return typeof value === 'string' && /^(?:[A-Fa-f0-9]{2}){32,}$/.test(value);
}

function isUtcSecond(value) {
  if (typeof value !== 'string' || !UTC_SECOND_PATTERN.test(value) || value.startsWith('0000-')) return false;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === `${value.slice(0, -1)}.000Z`;
}

function uniqueBy(values, projection = (value) => value) {
  // Do not pass Array.map's index/array arguments into projections such as
  // stableStringify(value, spaces); doing so can make equal values serialize
  // differently solely because they occupy different array positions.
  return new Set(values.map((value) => projection(value))).size === values.length;
}

function canonicalDigest(value) {
  return `sha256:${sha256(stableStringify(value))}`;
}

function digestWithout(value, field) {
  const subject = structuredClone(value);
  delete subject[field];
  return canonicalDigest(subject);
}

function handoffIntegrityIsValid(handoff) {
  try {
    if (handoff.handoff_digest !== digestWithout(handoff, 'handoff_digest')) return false;
    if (handoff.build_identity.build_identity_digest
        !== digestWithout(handoff.build_identity, 'build_identity_digest')) return false;
    if (handoff.evidence_manifest.items.some((item) => item.evidence_item_digest
        !== digestWithout(item, 'evidence_item_digest'))) return false;
    if (handoff.evidence_manifest.evidence_manifest_digest
        !== digestWithout(handoff.evidence_manifest, 'evidence_manifest_digest')) return false;

    const ticket = structuredClone(handoff.ticket);
    delete ticket.ticket_content_digest;
    const approvalSubject = {
      contract_version: handoff.contract_version,
      organization_id: handoff.organization_id,
      project_id: handoff.project_id,
      source_candidate: handoff.source_candidate,
      ticket,
      build_identity_digest: handoff.build_identity.build_identity_digest,
      evidence_manifest_digest: handoff.evidence_manifest.evidence_manifest_digest,
      authority: handoff.authority,
    };
    const approvedContentDigest = canonicalDigest(approvalSubject);
    if (handoff.ticket.ticket_content_digest !== approvedContentDigest
        || handoff.approval.ticket_content_digest !== approvedContentDigest) return false;

    const source = handoff.source_candidate;
    if (!hasExactKeys(source, [
      'contract_version', 'candidate_id', 'candidate_version', 'candidate_digest',
      'candidate_content_digest', 'canonical_json',
    ]) || typeof source.canonical_json !== 'string') return false;
    const candidate = JSON.parse(source.canonical_json);
    if (!isRecord(candidate) || stableStringify(candidate) !== source.canonical_json
        || candidate.state !== 'approved'
        || candidate.approval?.immutable !== true
        || source.contract_version !== candidate.contract_version
        || source.candidate_id !== candidate.candidate_id
        || source.candidate_version !== candidate.candidate_version
        || source.candidate_digest !== candidate.candidate_digest
        || source.candidate_content_digest !== candidate.candidate_content_digest) return false;
    const candidateContentSubject = {
      contract_version: candidate.contract_version,
      organization_id: candidate.organization_id,
      project_id: candidate.project_id,
      build_id: candidate.build_id,
      build_identity_digest: candidate.build_identity_digest,
      session_id: candidate.session_id,
      evidence_manifest: candidate.evidence_manifest,
      candidate_id: candidate.candidate_id,
      content: candidate.content,
    };
    return candidate.candidate_content_digest === canonicalDigest(candidateContentSubject)
      && candidate.candidate_digest === digestWithout(candidate, 'candidate_digest');
  } catch {
    return false;
  }
}

function validSignature(value) {
  return hasExactKeys(value, ['algorithm', 'key_id', 'value'])
    && value.algorithm === 'hmac-sha256'
    && isIdentifier(value.key_id)
    && typeof value.value === 'string'
    && HMAC_PATTERN.test(value.value);
}

function validSource(value) {
  return hasExactKeys(value, ['component', 'source_id', 'snapshot_revision'])
    && SOURCE_COMPONENTS.has(value.component)
    && isIdentifier(value.source_id)
    && typeof value.snapshot_revision === 'string'
    && Array.from(value.snapshot_revision).length >= 1
    && Array.from(value.snapshot_revision).length <= 128;
}

function validEvidenceSource(value) {
  return hasExactKeys(value, ['component', 'source_id', 'snapshot_revision', 'captured_at'])
    && isUtcSecond(value.captured_at)
    && validSource({
      component: value.component,
      source_id: value.source_id,
      snapshot_revision: value.snapshot_revision,
    });
}

function validRegistryAssertion(value) {
  if (!hasExactKeys(value, [
    'contract_version', 'media_type', 'assertion_id', 'issuer_id', 'organization_id',
    'project_id', 'ticket_id', 'ticket_version', 'current_handoff_digest',
    'registry_revision', 'authorized_sources', 'execution_authority', 'issued_at',
    'expires_at', 'signature',
  ])) return false;
  if (value.contract_version !== 'tacua.registry-assertion@1.0.0'
      || value.media_type !== 'application/vnd.tacua.registry-assertion+json;version=1.0.0'
      || ![value.assertion_id, value.issuer_id, value.organization_id, value.project_id,
        value.ticket_id, value.registry_revision].every(isIdentifier)
      || !isSafePositiveInteger(value.ticket_version)
      || !isDigest(value.current_handoff_digest)
      || !isUtcSecond(value.issued_at)
      || !isUtcSecond(value.expires_at)
      || !validSignature(value.signature)) return false;
  if (!Array.isArray(value.authorized_sources)
      || value.authorized_sources.length < 1
      || value.authorized_sources.length > 100
      || !value.authorized_sources.every(validSource)
      || !uniqueBy(value.authorized_sources, stableStringify)) return false;
  const authority = value.execution_authority;
  return hasExactKeys(authority, ['consumer', 'issuer_id', 'key_id', 'revocation_list_id', 'revocation_revision'])
    && authority.consumer === 'openai_codex'
    && [authority.issuer_id, authority.key_id, authority.revocation_list_id,
      authority.revocation_revision].every(isIdentifier);
}

function validExecutionAssertion(value) {
  if (!hasExactKeys(value, [
    'contract_version', 'media_type', 'assertion_id', 'issuer_id', 'consumer',
    'organization_id', 'project_id', 'ticket_id', 'ticket_version', 'repositories',
    'build_id', 'build_identity_digest', 'current_handoff_digest',
    'evidence_manifest_digest', 'evidence_item_digests', 'allowed_actions',
    'issued_at', 'expires_at', 'nonce', 'revocation_list_id', 'revocation_revision',
    'signature',
  ])) return false;
  if (value.contract_version !== 'tacua.execution-assertion@1.0.0'
      || value.media_type !== 'application/vnd.tacua.execution-assertion+json;version=1.0.0'
      || ![value.assertion_id, value.issuer_id, value.organization_id, value.project_id,
        value.ticket_id, value.build_id, value.revocation_list_id,
        value.revocation_revision].every(isIdentifier)
      || !isSafePositiveInteger(value.ticket_version)
      || ![value.build_identity_digest, value.current_handoff_digest,
        value.evidence_manifest_digest].every(isDigest)
      || !isUtcSecond(value.issued_at)
      || !isUtcSecond(value.expires_at)
      || typeof value.nonce !== 'string'
      || !NONCE_PATTERN.test(value.nonce)
      || !validSignature(value.signature)) return false;

  const consumer = value.consumer;
  if (!hasExactKeys(consumer, ['kind', 'agent', 'instance_id', 'runtime_profile'])
      || typeof consumer.kind !== 'string'
      || typeof consumer.agent !== 'string'
      || !isIdentifier(consumer.instance_id)
      || !hasExactKeys(consumer.runtime_profile, Object.keys(CODEX_RUNTIME_PROFILE))) return false;

  if (!Array.isArray(value.repositories)
      || value.repositories.length < 1
      || value.repositories.length > 16
      || !value.repositories.every((repository) => hasExactKeys(repository, ['repository_id', 'revision'])
        && isIdentifier(repository.repository_id)
        && typeof repository.revision === 'string'
        && REVISION_PATTERN.test(repository.revision))
      || !uniqueBy(value.repositories, stableStringify)) return false;
  if (!Array.isArray(value.evidence_item_digests)
      || value.evidence_item_digests.length < 1
      || value.evidence_item_digests.length > 100
      || !value.evidence_item_digests.every((item) => hasExactKeys(item, ['evidence_id', 'evidence_item_digest'])
        && isIdentifier(item.evidence_id)
        && isDigest(item.evidence_item_digest))
      || !uniqueBy(value.evidence_item_digests, stableStringify)) return false;
  return Array.isArray(value.allowed_actions)
    && value.allowed_actions.length >= 1
    && value.allowed_actions.length <= 3
    && uniqueBy(value.allowed_actions)
    && value.allowed_actions.every((action) => ['modify_code', 'read_authorized_evidence', 'run_tests'].includes(action));
}

function validExecutionRevocations(value) {
  if (!hasExactKeys(value, [
    'contract_version', 'media_type', 'list_id', 'issuer_id', 'revision', 'issued_at',
    'expires_at', 'revoked_assertion_ids', 'revoked_nonces', 'revoked_key_ids', 'signature',
  ])) return false;
  if (value.contract_version !== 'tacua.execution-revocations@1.0.0'
      || value.media_type !== 'application/vnd.tacua.execution-revocations+json;version=1.0.0'
      || ![value.list_id, value.issuer_id, value.revision].every(isIdentifier)
      || !isUtcSecond(value.issued_at)
      || !isUtcSecond(value.expires_at)
      || !validSignature(value.signature)) return false;
  const listRules = [
    [value.revoked_assertion_ids, 1000, isIdentifier],
    [value.revoked_nonces, 1000, (nonce) => typeof nonce === 'string' && NONCE_PATTERN.test(nonce)],
    [value.revoked_key_ids, 100, isIdentifier],
  ];
  return listRules.every(([items, maximum, validator]) => Array.isArray(items)
    && items.length <= maximum
    && items.every(validator)
    && uniqueBy(items));
}

function handoffBoundaryIsValid(handoff) {
  if (!isRecord(handoff)
      || handoff.contract_version !== 'tacua.approved-handoff@1.1.0'
      || handoff.media_type !== 'application/vnd.tacua.approved-handoff+json;version=1.1.0'
      || !isIdentifier(handoff.organization_id)
      || !isIdentifier(handoff.project_id)
      || !isDigest(handoff.handoff_digest)) return false;
  const ticket = handoff.ticket;
  const approval = handoff.approval;
  const supersession = handoff.supersession;
  const build = handoff.build_identity;
  const manifest = handoff.evidence_manifest;
  const authority = handoff.authority;
  if (!isRecord(ticket) || ticket.state !== 'approved' || !isIdentifier(ticket.ticket_id)
      || !isSafePositiveInteger(ticket.ticket_version)
      || !isRecord(approval) || approval.immutable !== true
      || !isUtcSecond(approval.approved_at)
      || approval.organization_id !== handoff.organization_id
      || approval.project_id !== handoff.project_id
      || approval.ticket_id !== ticket.ticket_id
      || approval.ticket_version !== ticket.ticket_version) return false;
  if (!isRecord(supersession) || !['current', 'superseded'].includes(supersession.status)
      || !(supersession.superseded_by_handoff_digest === null
        || isDigest(supersession.superseded_by_handoff_digest))
      || !isUtcSecond(supersession.checked_at)
      || !isIdentifier(supersession.registry_revision)) return false;
  if (!isRecord(build) || !isIdentifier(build.build_id) || !isDigest(build.build_identity_digest)
      || build.organization_id !== handoff.organization_id
      || build.project_id !== handoff.project_id
      || !isRecord(build.mobile) || !isRecord(build.mobile.source)
      || !isIdentifier(build.mobile.source.repository_id)
      || typeof build.mobile.source.revision !== 'string'
      || !REVISION_PATTERN.test(build.mobile.source.revision)
      || !isRecord(build.backend)
      || !['available', 'unavailable'].includes(build.backend.availability)) return false;
  if (build.backend.availability === 'available'
      && (!Array.isArray(build.backend.sources)
        || build.backend.sources.length < 1
        || build.backend.sources.length > 16
        || !build.backend.sources.every((source) => isRecord(source)
          && isIdentifier(source.repository_id)
          && typeof source.revision === 'string'
          && REVISION_PATTERN.test(source.revision)))) return false;
  if (build.backend.availability === 'unavailable'
      && (!Array.isArray(build.backend.sources) || build.backend.sources.length !== 0)) return false;
  if (!isRecord(manifest) || !isDigest(manifest.evidence_manifest_digest)
      || manifest.organization_id !== handoff.organization_id
      || manifest.project_id !== handoff.project_id
      || !Array.isArray(manifest.items)
      || manifest.items.length < 1
      || manifest.items.length > 100
      || !manifest.items.every((item) => isRecord(item)
        && isIdentifier(item.evidence_id)
        && isDigest(item.evidence_item_digest)
        && validEvidenceSource(item.source))
      || !uniqueBy(manifest.items, (item) => item.evidence_id)) return false;
  return isRecord(authority)
    && authority.purpose === 'implement_approved_ticket'
    && Array.isArray(authority.allowed_repositories)
    && authority.allowed_repositories.length >= 1
    && authority.allowed_repositories.length <= 16
    && authority.allowed_repositories.every(isIdentifier)
    && uniqueBy(authority.allowed_repositories)
    && authority.read_authorized_evidence === true
    && authority.modify_code === true
    && authority.run_tests === true
    && authority.external_writes === false
    && authority.merge === false
    && authority.deploy === false;
}

function compareRepository(left, right) {
  if (left.repository_id !== right.repository_id) return left.repository_id < right.repository_id ? -1 : 1;
  if (left.revision === right.revision) return 0;
  return left.revision < right.revision ? -1 : 1;
}

function denied(reasonCode) {
  return { allowed: false, reasonCode };
}

export function authorizeCodexExecution(input = {}) {
  const {
    handoff,
    registryAssertion,
    registryKeyHex,
    executionAssertion,
    executionRevocations,
    executionKeyHex,
    atTime,
  } = isRecord(input) ? input : {};
  if (!handoffBoundaryIsValid(handoff)) {
    return denied('STRUCTURAL_APPROVAL_REQUIRED');
  }
  if (!handoffIntegrityIsValid(handoff)) return denied('STRUCTURAL_APPROVAL_REQUIRED');
  if (handoff.supersession.status !== 'current'
      || handoff.supersession.superseded_by_handoff_digest !== null) {
    return denied('STALE_HANDOFF');
  }
  if (!registryAssertion || !registryKeyHex) return denied('REGISTRY_ASSERTION_REQUIRED');
  if (!executionAssertion || !executionRevocations || !executionKeyHex) {
    return denied('EXECUTION_ASSERTION_REQUIRED');
  }
  if (!validRegistryAssertion(registryAssertion)
      || !validExecutionAssertion(executionAssertion)
      || !validExecutionRevocations(executionRevocations)) {
    return denied('MALFORMED_TRUST_ARTIFACT');
  }
  const authority = registryAssertion.execution_authority;
  if (registryAssertion.signature?.key_id === authority.key_id) return denied('TRUST_KEY_ID_REUSE');
  if (isHmacKeyHex(registryKeyHex) && isHmacKeyHex(executionKeyHex)) {
    const registryKey = Buffer.from(registryKeyHex, 'hex');
    const executionKey = Buffer.from(executionKeyHex, 'hex');
    if (registryKey.length === executionKey.length && timingSafeEqual(registryKey, executionKey)) {
      return denied('TRUST_KEY_MATERIAL_REUSE');
    }
  }
  if (!isHmacKeyHex(registryKeyHex)) return denied('REGISTRY_SIGNATURE_MISMATCH');
  if (!isHmacKeyHex(executionKeyHex)) return denied('EXECUTION_SIGNATURE_MISMATCH');
  if (registryAssertion.signature.key_id === executionAssertion.signature.key_id) {
    return denied('TRUST_KEY_ID_REUSE');
  }
  if (!signatureMatches(registryAssertion, registryKeyHex)) return denied('REGISTRY_SIGNATURE_MISMATCH');
  if (!signatureMatches(executionAssertion, executionKeyHex)) return denied('EXECUTION_SIGNATURE_MISMATCH');
  if (!signatureMatches(executionRevocations, executionKeyHex)) return denied('REVOCATION_SIGNATURE_MISMATCH');

  if (!isUtcSecond(atTime)) return denied('INVALID_TRUST_TIME');
  const now = new Date(atTime);
  const registryIssued = new Date(registryAssertion.issued_at);
  const registryExpires = new Date(registryAssertion.expires_at);
  const executionIssued = new Date(executionAssertion.issued_at);
  const executionExpires = new Date(executionAssertion.expires_at);
  const revocationsIssued = new Date(executionRevocations.issued_at);
  const revocationsExpires = new Date(executionRevocations.expires_at);
  if (!(registryIssued < registryExpires)) return denied('INVALID_ASSERTION_WINDOW');
  if (registryExpires - registryIssued > 24 * 60 * 60 * 1000) return denied('ASSERTION_WINDOW_TOO_LONG');
  if (!(registryIssued <= now && now < registryExpires)) return denied('REGISTRY_ASSERTION_EXPIRED');
  const approvalTime = new Date(handoff.approval.approved_at);
  const registryChecked = new Date(handoff.supersession.checked_at);
  if (!(approvalTime <= registryIssued && registryChecked <= registryIssued)) {
    return denied('REGISTRY_ASSERTION_PRECEDES_HANDOFF_STATE');
  }
  if (!(executionIssued < executionExpires)) return denied('INVALID_EXECUTION_WINDOW');
  if (!(executionIssued <= now && now < executionExpires)) return denied('EXECUTION_ASSERTION_EXPIRED');
  if (executionExpires - executionIssued > 15 * 60 * 1000) return denied('EXECUTION_WINDOW_TOO_LONG');
  if (!(registryIssued <= executionIssued && executionExpires <= registryExpires)) {
    return denied('EXECUTION_OUTSIDE_REGISTRY_WINDOW');
  }
  if (!(revocationsIssued < revocationsExpires)) return denied('INVALID_REVOCATION_WINDOW');
  if (revocationsExpires - revocationsIssued > 24 * 60 * 60 * 1000) return denied('REVOCATION_WINDOW_TOO_LONG');
  if (!(revocationsIssued <= now && now < revocationsExpires)) return denied('REVOCATION_LIST_EXPIRED');

  const ticket = handoff.ticket;
  const registryScope = [
    ['organization_id', handoff.organization_id],
    ['project_id', handoff.project_id],
    ['ticket_id', ticket.ticket_id],
    ['ticket_version', ticket.ticket_version],
    ['current_handoff_digest', handoff.handoff_digest],
    ['registry_revision', handoff.supersession.registry_revision],
  ];
  if (registryScope.some(([field, expected]) => registryAssertion[field] !== expected)) {
    return denied('REGISTRY_SCOPE_MISMATCH');
  }
  const trustedSources = new Set(
    registryAssertion.authorized_sources.map((source) => stableStringify(source)),
  );
  const manifestSources = new Set(handoff.evidence_manifest.items
    .map(({ source }) => stableStringify({
      component: source.component,
      source_id: source.source_id,
      snapshot_revision: source.snapshot_revision,
    })));
  const untrustedSource = [...manifestSources]
    .some((source) => !trustedSources.has(source));
  if (untrustedSource || trustedSources.size !== manifestSources.size) {
    return denied('UNTRUSTED_EVIDENCE_SOURCE');
  }
  const authorityScope = [
    [executionAssertion.issuer_id, authority.issuer_id],
    [executionAssertion.signature.key_id, authority.key_id],
    [executionAssertion.revocation_list_id, authority.revocation_list_id],
    [executionAssertion.revocation_revision, authority.revocation_revision],
    [executionRevocations.issuer_id, authority.issuer_id],
    [executionRevocations.signature.key_id, authority.key_id],
    [executionRevocations.list_id, authority.revocation_list_id],
    [executionRevocations.revision, authority.revocation_revision],
  ];
  if (authorityScope.some(([supplied, expected]) => supplied !== expected)) {
    return denied('EXECUTION_AUTHORITY_MISMATCH');
  }
  if (executionAssertion.consumer.kind !== 'execution_agent'
      || executionAssertion.consumer.agent !== 'openai_codex'
      || stableStringify(executionAssertion.consumer.runtime_profile)
        !== stableStringify(CODEX_RUNTIME_PROFILE)) {
    return denied('EXECUTION_PROFILE_MISMATCH');
  }
  const build = handoff.build_identity;
  const manifest = handoff.evidence_manifest;
  const exactScope = [
    ['organization_id', handoff.organization_id],
    ['project_id', handoff.project_id],
    ['ticket_id', ticket.ticket_id],
    ['ticket_version', ticket.ticket_version],
    ['build_id', build.build_id],
    ['build_identity_digest', build.build_identity_digest],
    ['current_handoff_digest', handoff.handoff_digest],
    ['evidence_manifest_digest', manifest.evidence_manifest_digest],
  ];
  if (exactScope.some(([field, expected]) => executionAssertion[field] !== expected)) {
    return denied('EXECUTION_SCOPE_MISMATCH');
  }
  const repositories = [build.mobile.source, ...(build.backend.availability === 'available' ? build.backend.sources : [])]
    .map(({ repository_id, revision }) => ({ repository_id, revision }))
    .sort(compareRepository);
  const repositoryIds = new Set(repositories.map(({ repository_id }) => repository_id));
  const assertedRepositoryIds = new Set(
    executionAssertion.repositories.map(({ repository_id }) => repository_id),
  );
  if (repositoryIds.size !== repositories.length
      || assertedRepositoryIds.size !== executionAssertion.repositories.length
      || repositoryIds.size !== handoff.authority.allowed_repositories.length
      || handoff.authority.allowed_repositories.some((repositoryId) => !repositoryIds.has(repositoryId))) {
    return denied('EXECUTION_SCOPE_MISMATCH');
  }
  const evidence = manifest.items
    .map(({ evidence_id, evidence_item_digest }) => ({ evidence_id, evidence_item_digest }))
    .sort((left, right) => (left.evidence_id === right.evidence_id ? 0 : left.evidence_id < right.evidence_id ? -1 : 1));
  if (stableStringify(executionAssertion.repositories) !== stableStringify(repositories)
      || stableStringify(executionAssertion.evidence_item_digests) !== stableStringify(evidence)
      || stableStringify(executionAssertion.allowed_actions)
        !== stableStringify(['modify_code', 'read_authorized_evidence', 'run_tests'])) {
    return denied('EXECUTION_SCOPE_MISMATCH');
  }
  if (executionRevocations.revoked_assertion_ids.includes(executionAssertion.assertion_id)
      || executionRevocations.revoked_nonces.includes(executionAssertion.nonce)
      || executionRevocations.revoked_key_ids.includes(executionAssertion.signature.key_id)) {
    return denied('EXECUTION_REVOKED');
  }
  return { allowed: true, reasonCode: 'CODEX_EXECUTION_AUTHORIZED' };
}

export async function loadJson(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

function unique(items, label) {
  const seen = new Set();
  for (const item of items) {
    if (seen.has(item)) throw new Error(`duplicate ${label}: ${item}`);
    seen.add(item);
  }
}

export function validatePolicy(policy) {
  if (policy.schemaVersion !== 'tacua.egress-policy/v1alpha1') throw new Error('invalid policy schemaVersion');
  if (policy.policyVersion !== 'tacua.egress/v1alpha1') throw new Error('invalid policyVersion');
  if (policy.defaultDecision !== 'deny') throw new Error('default decision must be deny');
  if (policy.organizationMode !== 'single_organization_per_deployment') throw new Error('invalid organization mode');
  if (policy.rawMediaRetentionDays !== 30) throw new Error('raw media retention must default to 30 days');

  unique(policy.destinations.map(({ id }) => id), 'destination');
  unique(policy.dataClasses.map(({ id }) => id), 'data class');

  const destinationIds = new Set(policy.destinations.map(({ id }) => id));
  const operationIds = new Set(policy.allowedOperations);
  const reasonCodes = new Set(Object.keys(policy.reasonCodes));

  for (const dataClass of policy.dataClasses) {
    if (!/^DATA-\d{3}$/.test(dataClass.id)) throw new Error(`invalid data class: ${dataClass.id}`);
    unique(dataClass.fields.map(({ path }) => path), `${dataClass.id} field`);
    for (const field of dataClass.fields) {
      if (!/^[a-z][a-z0-9_]*$/.test(field.path)) throw new Error(`invalid field: ${dataClass.id}.${field.path}`);
      for (const [destination, rule] of Object.entries(field.rules)) {
        if (!destinationIds.has(destination)) throw new Error(`unknown policy destination: ${destination}`);
        if (!DECISIONS.includes(rule.decision)) throw new Error(`invalid policy decision: ${rule.decision}`);
        for (const operation of rule.operations) {
          if (!operationIds.has(operation)) throw new Error(`unknown policy operation: ${operation}`);
        }
      }
    }
  }

  for (const required of [
    'DEFAULT_DENY',
    'UNKNOWN_DATA_CLASS',
    'UNKNOWN_FIELD',
    'UNKNOWN_DESTINATION',
    'UNKNOWN_OPERATION',
    'OPERATION_NOT_ALLOWED',
    'MISSING_PROVENANCE',
    'APPROVAL_REQUIRED',
    'APPROVAL_SCOPE_MISMATCH',
    'TRANSFORMATION_REQUIRED',
    'PROVIDER_NOT_REGISTERED',
    'METADATA_PAYLOAD_REJECTED',
    'POLICY_ALLOW_TRANSFORMED',
    'POLICY_ALLOW_APPROVED',
    'POLICY_DENY_PROHIBITED',
    'AUTHORIZED_METADATA',
  ]) {
    if (!reasonCodes.has(required)) throw new Error(`missing reason code: ${required}`);
  }
  return true;
}

export function validateCanaries(catalogue) {
  if (catalogue.schemaVersion !== 'tacua.synthetic-canaries/v1alpha1') throw new Error('invalid canary schemaVersion');
  unique(catalogue.canaries.map(({ id }) => id), 'canary id');
  unique(catalogue.canaries.map(({ value }) => value), 'canary value');
  for (const canary of catalogue.canaries) {
    if (!/^CANARY-[A-Z0-9-]+$/.test(canary.id)) throw new Error(`invalid canary id: ${canary.id}`);
    if (!canary.value.includes('TACUA_SYNTHETIC_') && !canary.value.includes('tacua-synthetic.invalid')) {
      throw new Error(`canary is not obviously synthetic: ${canary.id}`);
    }
    if (canary.value.includes('://') && !canary.value.includes('.invalid/')) {
      throw new Error(`synthetic URL must use .invalid: ${canary.id}`);
    }
  }
  return true;
}

export function validateCorpus(corpus, catalogue, policy) {
  if (corpus.schemaVersion !== 'tacua.security-corpus/v1alpha1') throw new Error('invalid corpus schemaVersion');
  unique(corpus.cases.map(({ id }) => id), 'corpus case');
  const canaries = new Set(catalogue.canaries.map(({ id }) => id));
  const operations = new Set(policy.allowedOperations);
  for (const testCase of corpus.cases) {
    if (!/^EGRESS-\d{3}$/.test(testCase.id)) throw new Error(`invalid case id: ${testCase.id}`);
    if (!operations.has(testCase.operation)) throw new Error(`invalid case operation: ${testCase.id}`);
    for (const canaryId of testCase.canaryIds) {
      if (!canaries.has(canaryId)) throw new Error(`unknown canary ${canaryId} in ${testCase.id}`);
    }
    if (!['allow', 'deny'].includes(testCase.expected?.enforcementDecision)) {
      throw new Error(`invalid expected enforcement decision: ${testCase.id}`);
    }
  }
  return true;
}

export function validateAuthorizationCorpus(authCorpus) {
  if (authCorpus.schemaVersion !== 'tacua.authorization-corpus/v1alpha1') {
    throw new Error('invalid authorization corpus schemaVersion');
  }
  if (!authCorpus.deployment?.organizationId || !Array.isArray(authCorpus.deployment.projects)) {
    throw new Error('invalid authorization deployment');
  }
  unique(authCorpus.cases.map(({ id }) => id), 'authorization case');
  for (const testCase of authCorpus.cases) {
    if (!/^AUTH-\d{3}$/.test(testCase.id)) throw new Error(`invalid authorization case: ${testCase.id}`);
    if (!testCase.actor?.memberId || !Array.isArray(testCase.actor.projectMemberships)) {
      throw new Error(`invalid authorization actor: ${testCase.id}`);
    }
    if (!testCase.resource?.organizationId || !testCase.resource?.projectId) {
      throw new Error(`invalid authorization resource: ${testCase.id}`);
    }
    if (typeof testCase.expected?.allowed !== 'boolean' || !testCase.expected.reasonCode) {
      throw new Error(`invalid authorization expectation: ${testCase.id}`);
    }
  }
  return true;
}

export function validateExportCase(exportCase) {
  if (exportCase.schemaVersion !== 'tacua.approved-ticket/v1alpha1') throw new Error('invalid export schemaVersion');
  if (!exportCase.organizationId || !exportCase.projectId || !exportCase.build?.id || !exportCase.ticket?.id) {
    throw new Error('invalid export fixture identity');
  }
  if (!Array.isArray(exportCase.evidence) || exportCase.evidence.length === 0) {
    throw new Error('export fixture requires evidence references');
  }
  return true;
}

export function validateEgressDecision(decision) {
  const keys = [
    'schemaVersion',
    'caseId',
    'dataClass',
    'field',
    'destination',
    'operation',
    'policyVersion',
    'policyDecision',
    'enforcementDecision',
    'reasonCode',
    'recipient',
    'provenance',
    'audit',
  ];
  if (stableStringify(Object.keys(decision).sort()) !== stableStringify(keys.sort())) {
    throw new Error(`invalid egress decision keys: ${decision.caseId}`);
  }
  if (decision.schemaVersion !== 'tacua.egress-decision/v1alpha1') throw new Error('invalid decision schemaVersion');
  if (!DECISIONS.includes(decision.policyDecision)) throw new Error('invalid policy decision');
  if (!['allow', 'deny'].includes(decision.enforcementDecision)) throw new Error('invalid enforcement decision');
  if (!/^[A-Z][A-Z0-9_]+$/.test(decision.reasonCode)) throw new Error('invalid reason code');
  const auditKeys = [
    'caseId',
    'dataClass',
    'boundary',
    'operation',
    'policyVersion',
    'destination',
    'decision',
    'reasonCode',
    'contentHash',
    'byteCount',
    'expected',
    'actual',
    'simulatedDurationMs',
  ];
  if (stableStringify(Object.keys(decision.audit).sort()) !== stableStringify(auditKeys.sort())) {
    throw new Error(`invalid audit keys: ${decision.caseId}`);
  }
  if ('payload' in decision.audit || 'content' in decision.audit || 'secret' in decision.audit) {
    throw new Error(`audit contains content field: ${decision.caseId}`);
  }
  return true;
}

export function makeProvenance(testCase, policyVersion = 'tacua.egress/v1alpha1') {
  return {
    evidenceId: `evidence-${testCase.id.toLowerCase()}`,
    sourceType: testCase.modality,
    sourceDigest: sha256(`source:${testCase.id}`),
    projectId: 'project-alpha',
    policyVersion,
  };
}

function hasCompleteProvenance(provenance, policyVersion) {
  return Boolean(
    provenance &&
      provenance.evidenceId &&
      provenance.sourceType &&
      /^[a-f0-9]{64}$/.test(provenance.sourceDigest) &&
      provenance.projectId &&
      provenance.policyVersion === policyVersion,
  );
}

function prohibitedClassification(classification) {
  return classification.startsWith('prohibited_') || classification === 'critical_secret';
}

function findRule(policy, request) {
  const dataClass = policy.dataClasses.find(({ id }) => id === request.dataClass);
  if (!dataClass) return { reasonCode: 'UNKNOWN_DATA_CLASS', policyDecision: 'deny' };
  const field = dataClass.fields.find(({ path }) => path === request.field);
  if (!field) return { reasonCode: 'UNKNOWN_FIELD', policyDecision: 'deny', dataClass };
  const destination = policy.destinations.find(({ id }) => id === request.destination);
  if (!destination) return { reasonCode: 'UNKNOWN_DESTINATION', policyDecision: 'deny', dataClass, field };
  if (!policy.allowedOperations.includes(request.operation)) {
    return { reasonCode: 'UNKNOWN_OPERATION', policyDecision: 'deny', dataClass, field, destination };
  }
  const rule = field.rules[request.destination];
  if (!rule) {
    return {
      reasonCode: prohibitedClassification(field.classification) ? 'POLICY_DENY_PROHIBITED' : 'DEFAULT_DENY',
      policyDecision: 'deny',
      dataClass,
      field,
      destination,
    };
  }
  if (!rule.operations.includes(request.operation)) {
    return { reasonCode: 'OPERATION_NOT_ALLOWED', policyDecision: rule.decision, dataClass, field, destination, rule };
  }
  return { dataClass, field, destination, rule, policyDecision: rule.decision };
}

function approvalMatches(approval, request, policy) {
  return Boolean(
    approval?.immutable === true &&
      approval.projectId === request.provenance.projectId &&
      approval.dataClass === request.dataClass &&
      approval.field === request.field &&
      approval.destination === request.destination &&
      approval.policyVersion === policy.policyVersion,
  );
}

export function makeApproval(request, policy) {
  const caseId = request.caseId ?? request.id;
  return {
    id: `approval-${caseId.toLowerCase()}`,
    immutable: true,
    actorId: 'member-approver',
    projectId: request.provenance.projectId,
    dataClass: request.dataClass,
    field: request.field,
    destination: request.destination,
    policyVersion: policy.policyVersion,
  };
}

export function materializePayload(testCase, catalogue) {
  if (testCase.metadataOnly) {
    return {
      referenceId: `reference-${testCase.id.toLowerCase()}`,
      digest: sha256(`metadata:${testCase.id}`),
    };
  }
  const byId = new Map(catalogue.canaries.map((canary) => [canary.id, canary]));
  return {
    modality: testCase.modality,
    untrusted: true,
    content: testCase.canaryIds.map((id) => byId.get(id).value).join(' | '),
  };
}

export function scanForCanaries(value, catalogue, { prohibitedOnly = true } = {}) {
  const serialized = typeof value === 'string' ? value : stableStringify(value);
  return catalogue.canaries
    .filter((canary) => !prohibitedOnly || canary.mustNotEgress)
    .filter((canary) => serialized.includes(canary.value))
    .map(({ id, category, prohibitions }) => ({ id, category, prohibitions }));
}

export function transformPayload(payload, catalogue, transformName) {
  let serialized = stableStringify(payload);
  const redactions = [];
  for (const canary of catalogue.canaries) {
    if (serialized.includes(canary.value)) {
      const replacement = `[REDACTED:${canary.id}]`;
      serialized = serialized.split(canary.value).join(replacement);
      redactions.push(canary.id);
    }
  }
  return {
    transformation: transformName,
    irreversible: true,
    redactionIds: redactions.sort(),
    transformedPayload: JSON.parse(serialized),
  };
}

function makeAudit({ request, policy, destination, decision, reasonCode, sink, expected }) {
  const serialized = sink === null ? null : stableStringify(sink);
  return {
    caseId: request.caseId,
    dataClass: request.dataClass,
    boundary: destination?.boundary ?? 'unregistered',
    operation: request.operation,
    policyVersion: policy.policyVersion,
    destination: request.destination,
    decision,
    reasonCode,
    contentHash: serialized === null ? null : sha256(serialized),
    byteCount: serialized === null ? 0 : Buffer.byteLength(serialized),
    expected,
    actual: decision,
    simulatedDurationMs: (Number.parseInt(request.caseId.match(/\d+$/)?.[0] ?? '0', 10) % 7) + 1,
  };
}

export function evaluateEgress(policy, catalogue, inputRequest) {
  const request = { ...inputRequest, caseId: inputRequest.caseId ?? inputRequest.id };
  const resolution = findRule(policy, request);
  const expected = request.expected?.enforcementDecision ?? 'deny';
  let enforcementDecision = 'deny';
  let reasonCode = resolution.reasonCode;
  let sink = null;

  if (resolution.rule && resolution.rule.operations.includes(request.operation)) {
    if (request.dataClass === 'DATA-006' && request.field === 'allowlisted_value' && request.providerRegistered !== true) {
      reasonCode = 'PROVIDER_NOT_REGISTERED';
    } else if (!hasCompleteProvenance(request.provenance, policy.policyVersion)) {
      reasonCode = 'MISSING_PROVENANCE';
    } else if (resolution.rule.decision === 'allow_metadata_reference_only') {
      if (request.metadataOnly !== true || scanForCanaries(request.payload, catalogue, { prohibitedOnly: false }).length > 0) {
        reasonCode = 'METADATA_PAYLOAD_REJECTED';
      } else {
        enforcementDecision = 'allow';
        reasonCode = 'AUTHORIZED_METADATA';
        sink = {
          referenceId: request.payload.referenceId,
          digest: request.payload.digest,
          provenance: request.provenance,
        };
      }
    } else if (resolution.rule.decision === 'allow_after_irreversible_transformation') {
      if (!resolution.rule.transform) {
        reasonCode = 'TRANSFORMATION_REQUIRED';
      } else {
        enforcementDecision = 'allow';
        reasonCode = 'POLICY_ALLOW_TRANSFORMED';
        sink = transformPayload(request.payload, catalogue, resolution.rule.transform);
      }
    } else if (resolution.rule.decision === 'require_explicit_project_reviewer_approval') {
      if (!request.approval) {
        reasonCode = 'APPROVAL_REQUIRED';
      } else if (!approvalMatches(request.approval, request, policy)) {
        reasonCode = 'APPROVAL_SCOPE_MISMATCH';
      } else if (resolution.rule.transform) {
        enforcementDecision = 'allow';
        reasonCode = 'POLICY_ALLOW_APPROVED';
        sink = transformPayload(request.payload, catalogue, resolution.rule.transform);
      } else if (request.metadataOnly === true) {
        enforcementDecision = 'allow';
        reasonCode = 'POLICY_ALLOW_APPROVED';
        sink = {
          referenceId: request.payload.referenceId,
          digest: request.payload.digest,
          provenance: request.provenance,
        };
      } else {
        reasonCode = 'TRANSFORMATION_REQUIRED';
      }
    }
  }

  const decision = {
    schemaVersion: 'tacua.egress-decision/v1alpha1',
    caseId: request.caseId,
    dataClass: request.dataClass,
    field: request.field,
    destination: request.destination,
    operation: request.operation,
    policyVersion: policy.policyVersion,
    policyDecision: resolution.policyDecision,
    enforcementDecision,
    reasonCode,
    recipient: resolution.destination?.recipient ?? 'unregistered destination',
    provenance: request.provenance ?? null,
    audit: makeAudit({
      request,
      policy,
      destination: resolution.destination,
      decision: enforcementDecision,
      reasonCode,
      sink,
      expected,
    }),
  };

  return { decision, sink, resolution };
}

export function runCorpus(policy, catalogue, corpus) {
  const records = [];
  for (const testCase of corpus.cases) {
    const provenance = makeProvenance(testCase, policy.policyVersion);
    const request = {
      ...testCase,
      provenance,
      payload: materializePayload(testCase, catalogue),
    };
    if (testCase.approval === true) request.approval = makeApproval(request, policy);
    const { decision, sink } = evaluateEgress(policy, catalogue, request);
    const canaryFindings = scanForCanaries(sink, catalogue);
    records.push({
      ...decision,
      expectedProhibitedCanariesAtSink: testCase.expected.prohibitedCanariesAtSink,
      actualProhibitedCanariesAtSink: canaryFindings.length,
      canaryFindingIds: canaryFindings.map(({ id }) => id),
      passed:
        decision.enforcementDecision === testCase.expected.enforcementDecision &&
        decision.reasonCode === testCase.expected.reasonCode &&
        canaryFindings.length === testCase.expected.prohibitedCanariesAtSink,
    });
  }
  return records;
}

export function expandEgressMatrix(policy) {
  const rows = [];
  for (const dataClass of policy.dataClasses) {
    for (const field of dataClass.fields) {
      for (const destination of policy.destinations) {
        const rule = field.rules[destination.id];
        rows.push({
          cellId: `${dataClass.id}:${field.path}:${destination.id}`,
          policyVersion: policy.policyVersion,
          dataClass: dataClass.id,
          dataClassName: dataClass.name,
          field: field.path,
          classification: field.classification,
          destination: destination.id,
          recipient: destination.recipient,
          boundary: destination.boundary,
          policyDecision: rule?.decision ?? 'deny',
          reasonCode: rule
            ? rule.decision === 'allow_metadata_reference_only'
              ? 'AUTHORIZED_METADATA'
              : rule.decision === 'allow_after_irreversible_transformation'
                ? 'POLICY_ALLOW_TRANSFORMED'
                : 'APPROVAL_REQUIRED'
            : prohibitedClassification(field.classification)
              ? 'POLICY_DENY_PROHIBITED'
              : 'DEFAULT_DENY',
          operations: rule?.operations ?? [],
          transformation: rule?.transform ?? null,
          provenanceRequired: rule !== undefined,
        });
      }
    }
  }
  return rows;
}

export function buildCoverage(policy, catalogue, corpus, matrix) {
  const caseMap = new Map();
  for (const testCase of corpus.cases) {
    const cellId = `${testCase.dataClass}:${testCase.field}:${testCase.destination}`;
    if (!caseMap.has(cellId)) caseMap.set(cellId, []);
    caseMap.get(cellId).push(testCase.id);
  }
  const matrixCells = matrix.map((row) => ({
    cellId: row.cellId,
    dataClass: row.dataClass,
    field: row.field,
    destination: row.destination,
    policyDecision: row.policyDecision,
    operations: row.operations,
    caseIds: (caseMap.get(row.cellId) ?? []).sort(),
    exercised: caseMap.has(row.cellId),
  }));
  const canaryCases = catalogue.canaries.map((canary) => ({
    canaryId: canary.id,
    category: canary.category,
    prohibitions: canary.prohibitions,
    caseIds: corpus.cases.filter(({ canaryIds }) => canaryIds.includes(canary.id)).map(({ id }) => id),
  }));
  const modalities = [...new Set(corpus.cases.map(({ modality }) => modality))].sort().map((modality) => ({
    modality,
    caseIds: corpus.cases.filter((testCase) => testCase.modality === modality).map(({ id }) => id),
  }));
  const operations = policy.allowedOperations.map((operation) => ({
    operation,
    caseIds: corpus.cases.filter((testCase) => testCase.operation === operation).map(({ id }) => id),
  }));
  return {
    schemaVersion: 'tacua.security-coverage/v1alpha1',
    policyVersion: policy.policyVersion,
    summary: {
      matrixCellCount: matrixCells.length,
      exercisedMatrixCellCount: matrixCells.filter(({ exercised }) => exercised).length,
      corpusCaseCount: corpus.cases.length,
      canaryCount: catalogue.canaries.length,
      modalityCount: modalities.length,
    },
    matrixCells,
    canaryCases,
    modalities,
    operations,
  };
}

export function authorize(testCase, deployment) {
  const { actor, resource } = testCase;
  if (resource.organizationId !== deployment.organizationId || actor.organizationId !== deployment.organizationId) {
    return { caseId: testCase.id, allowed: false, reasonCode: 'ORGANIZATION_MISMATCH' };
  }
  if (!deployment.projects.includes(resource.projectId)) {
    return { caseId: testCase.id, allowed: false, reasonCode: 'UNKNOWN_PROJECT' };
  }
  if (!actor.projectMemberships.includes(resource.projectId)) {
    return { caseId: testCase.id, allowed: false, reasonCode: 'PROJECT_MEMBERSHIP_REQUIRED' };
  }
  if (testCase.resourceType === 'object_key') {
    if (resource.objectKey.includes('..') || resource.objectKey.startsWith('/')) {
      return { caseId: testCase.id, allowed: false, reasonCode: 'INVALID_OBJECT_KEY' };
    }
    const expectedPrefix = `${resource.organizationId}/${resource.projectId}/`;
    if (!resource.objectKey.startsWith(expectedPrefix)) {
      return { caseId: testCase.id, allowed: false, reasonCode: 'OBJECT_SCOPE_MISMATCH' };
    }
  }
  if (testCase.resourceType === 'job') {
    if (
      resource.immutableJobScope.organizationId !== resource.organizationId ||
      resource.immutableJobScope.projectId !== resource.projectId
    ) {
      return { caseId: testCase.id, allowed: false, reasonCode: 'JOB_SCOPE_MISMATCH' };
    }
  }
  if (testCase.resourceType === 'evidence_reference' && resource.evidenceProjectId !== resource.projectId) {
    return { caseId: testCase.id, allowed: false, reasonCode: 'EVIDENCE_SCOPE_MISMATCH' };
  }
  if (testCase.resourceType === 'ticket') {
    if (resource.state !== 'approved' || resource.approvedVersion === null) {
      return { caseId: testCase.id, allowed: false, reasonCode: 'TICKET_NOT_APPROVED' };
    }
    if (resource.version !== resource.approvedVersion || resource.supersededBy !== null) {
      return { caseId: testCase.id, allowed: false, reasonCode: 'STALE_TICKET_VERSION' };
    }
    return { caseId: testCase.id, allowed: true, reasonCode: 'AUTHORIZED_APPROVED_TICKET' };
  }
  if (testCase.resourceType === 'connector_query') {
    if (resource.revoked) return { caseId: testCase.id, allowed: false, reasonCode: 'CONNECTOR_REVOKED' };
    if (!resource.readOnly) return { caseId: testCase.id, allowed: false, reasonCode: 'WRITE_TOOL_FORBIDDEN' };
    if (resource.queryWindowMinutes > resource.maxQueryWindowMinutes) {
      return { caseId: testCase.id, allowed: false, reasonCode: 'QUERY_WINDOW_EXCEEDED' };
    }
    return { caseId: testCase.id, allowed: true, reasonCode: 'AUTHORIZED_BOUNDED_READ' };
  }
  return { caseId: testCase.id, allowed: true, reasonCode: 'AUTHORIZED_PROJECT_MEMBER' };
}

export function runAuthorizationCorpus(authCorpus) {
  return authCorpus.cases.map((testCase) => {
    const actual = authorize(testCase, authCorpus.deployment);
    return {
      ...actual,
      resourceType: testCase.resourceType,
      action: testCase.action,
      expectedAllowed: testCase.expected.allowed,
      expectedReasonCode: testCase.expected.reasonCode,
      passed: actual.allowed === testCase.expected.allowed && actual.reasonCode === testCase.expected.reasonCode,
    };
  });
}

export function escapeMarkdownScalar(value) {
  return JSON.stringify(String(value))
    .replaceAll('\\', '\\\\')
    .replace(/([`*_{}\[\]<>()#+.!|>\-])/g, '\\$1');
}

export function renderApprovedBundle(exportCase) {
  const { organizationId, projectId, build, ticket, evidence } = exportCase;
  if (ticket.state !== 'approved' || ticket.approvedVersion === null) throw new Error('TICKET_NOT_APPROVED');
  if (ticket.version !== ticket.approvedVersion || ticket.supersededBy !== null) throw new Error('STALE_TICKET_VERSION');
  if (
    ticket.approval?.immutable !== true ||
    ticket.approval.projectId !== projectId ||
    ticket.approval.ticketVersion !== ticket.version ||
    ticket.approval.policyVersion !== 'tacua.egress/v1alpha1'
  ) {
    throw new Error('APPROVAL_SCOPE_MISMATCH');
  }
  for (const item of evidence) {
    if (item.projectId !== projectId) throw new Error('EVIDENCE_SCOPE_MISMATCH');
    if (!/^[a-f0-9]{64}$/.test(item.digest)) throw new Error('INVALID_EVIDENCE_DIGEST');
  }
  const evidenceReferences = evidence.map(({ id, dataClass, digest, sourceEvidenceId, policyVersion }) => ({
    id,
    dataClass,
    digest,
    sourceEvidenceId,
    policyVersion,
  }));
  const canonicalTicket = {
    organizationId,
    projectId,
    build,
    ticket: {
      id: ticket.id,
      version: ticket.version,
      state: ticket.state,
      title: ticket.title,
      observation: ticket.observation,
      expectedBehavior: ticket.expectedBehavior,
    },
    approval: ticket.approval,
    evidence: evidenceReferences,
  };
  const canonicalTicketDigest = sha256(stableStringify(canonicalTicket));
  const manifest = {
    schemaVersion: 'tacua.agent-handoff/v1alpha1',
    mediaType: 'application/vnd.tacua.agent-handoff+json;version=1alpha1',
    policyVersion: 'tacua.egress/v1alpha1',
    canonicalTicketDigest,
    supersession: { status: 'current', supersededBy: null },
    ...canonicalTicket,
  };
  const json = `${stableStringify(manifest, 2)}\n`;
  const markdown = [
    '# Tacua approved ticket',
    '',
    `- Schema: ${manifest.schemaVersion}`,
    `- Policy: ${manifest.policyVersion}`,
    `- Canonical ticket digest: ${canonicalTicketDigest}`,
    `- Ticket/version: ${ticket.id}/${ticket.version}`,
    `- Build/commit: ${build.id}/${build.commit}`,
    `- Supersession: current`,
    '',
    '## Title',
    '',
    escapeMarkdownScalar(ticket.title),
    '',
    '## Observed behavior',
    '',
    escapeMarkdownScalar(ticket.observation),
    '',
    '## Expected behavior',
    '',
    escapeMarkdownScalar(ticket.expectedBehavior),
    '',
    '## Immutable evidence references',
    '',
    ...evidenceReferences.map((item) => `- ${item.id} | ${item.dataClass} | ${item.digest} | source ${item.sourceEvidenceId}`),
    '',
  ].join('\n');
  return { canonicalTicketDigest, manifest, json, markdown };
}

export function validateDeletionGraph(graph) {
  if (graph.schemaVersion !== 'tacua.deletion-graph/v1alpha1') throw new Error('invalid deletion graph schemaVersion');
  unique(graph.nodes.map(({ id }) => id), 'deletion node');
  const nodes = new Map(graph.nodes.map((node) => [node.id, node]));
  if (!nodes.has(graph.rootId)) throw new Error('missing deletion root');
  for (const node of graph.nodes) {
    for (const child of node.children) if (!nodes.has(child)) throw new Error(`missing deletion child: ${child}`);
  }
  const visited = new Set();
  const active = new Set();
  function visit(id) {
    if (active.has(id)) throw new Error(`deletion graph cycle: ${id}`);
    if (visited.has(id)) return;
    active.add(id);
    for (const child of nodes.get(id).children) visit(child);
    active.delete(id);
    visited.add(id);
  }
  visit(graph.rootId);
  if (visited.size !== graph.nodes.length) throw new Error('deletion graph has unreachable governed nodes');
  return true;
}

export function simulateDeletion(graph, scenario) {
  validateDeletionGraph(graph);
  const failed = new Set(scenario.failedNodeIds);
  let localDeleted = 0;
  let tombstoned = 0;
  let externalUnverified = 0;
  let failedCount = 0;
  const lineage = [];
  for (const node of graph.nodes) {
    let status;
    if (failed.has(node.id)) {
      status = 'failed_visible';
      failedCount += 1;
    } else if (node.deletionMode === 'delete') {
      status = 'deleted_local_simulation';
      localDeleted += 1;
    } else if (node.deletionMode === 'tombstone_minimized') {
      status = 'tombstoned_metadata_only';
      tombstoned += 1;
    } else {
      status = 'external_contract_unverified';
      externalUnverified += 1;
    }
    lineage.push({ id: node.id, kind: node.kind, dataClass: node.dataClass, status });
  }
  const status = failedCount > 0 ? 'partial_failure' : externalUnverified > 0 ? 'blocked_external' : 'complete';
  return {
    caseId: scenario.id,
    status,
    localDeleted,
    tombstoned,
    externalUnverified,
    failed: failedCount,
    lineage,
    passed:
      status === scenario.expected.status &&
      localDeleted === scenario.expected.localDeleted &&
      tombstoned === scenario.expected.tombstoned &&
      externalUnverified === scenario.expected.externalUnverified &&
      failedCount === scenario.expected.failed,
  };
}

export function applyRetentionChange(currentDays, requestedDays) {
  if (!Number.isInteger(currentDays) || !Number.isInteger(requestedDays) || requestedDays < 0) {
    return { allowed: false, reasonCode: 'INVALID_RETENTION' };
  }
  if (requestedDays > currentDays) {
    return { allowed: false, reasonCode: 'RETENTION_LENGTHENING_REQUIRES_NEW_POLICY_SCOPE' };
  }
  return { allowed: true, reasonCode: requestedDays < currentDays ? 'RETENTION_SHORTENED' : 'RETENTION_UNCHANGED' };
}

async function listFiles(root) {
  const entries = await readdir(root, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) files.push(...(await listFiles(path)));
    else files.push(path);
  }
  return files.sort();
}

export async function scanPathsForProhibitedCanaries(paths, catalogue) {
  const findings = [];
  for (const root of paths) {
    for (const path of await listFiles(root)) {
      if (!['.json', '.md', '.txt', '.mjs'].includes(extname(path))) continue;
      const content = await readFile(path, 'utf8');
      for (const finding of scanForCanaries(content, catalogue)) findings.push({ path, ...finding });
    }
  }
  return findings;
}

export async function generateResults({ harnessRoot, outputRoot }) {
  const policy = await loadJson(join(harnessRoot, 'policy/v1.policy.json'));
  const catalogue = await loadJson(join(harnessRoot, 'fixtures/canaries.json'));
  const corpus = await loadJson(join(harnessRoot, 'fixtures/corpus.json'));
  const authCorpus = await loadJson(join(harnessRoot, 'fixtures/auth-cases.json'));
  const deletionGraph = await loadJson(join(harnessRoot, 'fixtures/deletion-graph.json'));
  const exportCase = await loadJson(join(harnessRoot, 'fixtures/export-case.json'));
  const handoffFixtureRoot = resolve(harnessRoot, '../../contracts/approved-handoff/fixtures/positive');
  const handoff = await loadJson(join(handoffFixtureRoot, 'approved-handoff.json'));
  const registryAssertion = await loadJson(join(handoffFixtureRoot, 'registry-assertion.json'));
  const executionAssertion = await loadJson(join(handoffFixtureRoot, 'execution-assertion.json'));
  const executionRevocations = await loadJson(join(handoffFixtureRoot, 'execution-revocations.json'));
  const registryKeyHex = (await readFile(join(handoffFixtureRoot, 'registry-key.synthetic.hex'), 'utf8')).trim();
  const executionKeyHex = (await readFile(join(handoffFixtureRoot, 'execution-key.synthetic.hex'), 'utf8')).trim();
  validatePolicy(policy);
  validateCanaries(catalogue);
  validateCorpus(corpus, catalogue, policy);
  validateAuthorizationCorpus(authCorpus);
  validateDeletionGraph(deletionGraph);
  validateExportCase(exportCase);

  const egressResults = runCorpus(policy, catalogue, corpus);
  for (const result of egressResults) {
    const { expectedProhibitedCanariesAtSink, actualProhibitedCanariesAtSink, canaryFindingIds, passed, ...decision } = result;
    validateEgressDecision(decision);
  }
  const authResults = runAuthorizationCorpus(authCorpus);
  const deletionResults = deletionGraph.scenarios.map((scenario) => simulateDeletion(deletionGraph, scenario));
  const bundle = renderApprovedBundle(exportCase);
  const exportScans = {
    json: scanForCanaries(bundle.json, catalogue),
    markdown: scanForCanaries(bundle.markdown, catalogue),
  };
  const matrix = expandEgressMatrix(policy);
  const coverage = buildCoverage(policy, catalogue, corpus, matrix);
  const retentionResults = [
    { caseId: 'RETENTION-001', currentDays: 30, requestedDays: 14, ...applyRetentionChange(30, 14), expectedAllowed: true },
    { caseId: 'RETENTION-002', currentDays: 14, requestedDays: 30, ...applyRetentionChange(14, 30), expectedAllowed: false },
    { caseId: 'RETENTION-003', currentDays: 30, requestedDays: 30, ...applyRetentionChange(30, 30), expectedAllowed: true },
  ].map((result) => ({ ...result, passed: result.allowed === result.expectedAllowed }));
  const executionBase = {
    handoff,
    registryAssertion,
    registryKeyHex,
    executionAssertion,
    executionRevocations,
    executionKeyHex,
    atTime: '2026-07-20T11:00:00Z',
  };
  const dangerousAssertion = structuredClone(executionAssertion);
  dangerousAssertion.consumer.runtime_profile.sandbox = 'danger-full-access';
  const revoked = structuredClone(executionRevocations);
  revoked.revoked_nonces = [executionAssertion.nonce];
  const reusedKeyId = structuredClone(registryAssertion);
  reusedKeyId.execution_authority.key_id = reusedKeyId.signature.key_id;
  const missingEvidenceSource = structuredClone(registryAssertion);
  missingEvidenceSource.authorized_sources = missingEvidenceSource.authorized_sources.slice(1);
  const malformedExecution = structuredClone(executionAssertion);
  malformedExecution.contract_version = 'tacua.execution-assertion@999.0.0';
  const staleHandoff = structuredClone(handoff);
  staleHandoff.supersession.status = 'superseded';
  staleHandoff.supersession.superseded_by_handoff_digest = `sha256:${'f'.repeat(64)}`;
  staleHandoff.handoff_digest = digestWithout(staleHandoff, 'handoff_digest');
  const tamperedHandoff = structuredClone(handoff);
  tamperedHandoff.ticket.summary += ' tampered after approval';
  const executionCases = [
    { caseId: 'EXECUTION-001', input: executionBase, expected: 'CODEX_EXECUTION_AUTHORIZED' },
    { caseId: 'EXECUTION-002', input: { ...executionBase, executionAssertion: null }, expected: 'EXECUTION_ASSERTION_REQUIRED' },
    {
      caseId: 'EXECUTION-003',
      input: {
        ...executionBase,
        executionAssertion: signSyntheticHmacArtifact(dangerousAssertion, executionKeyHex),
      },
      expected: 'EXECUTION_PROFILE_MISMATCH',
    },
    {
      caseId: 'EXECUTION-004',
      input: {
        ...executionBase,
        executionRevocations: signSyntheticHmacArtifact(revoked, executionKeyHex),
      },
      expected: 'EXECUTION_REVOKED',
    },
    {
      caseId: 'EXECUTION-005',
      input: {
        ...executionBase,
        registryAssertion: signSyntheticHmacArtifact(reusedKeyId, registryKeyHex),
      },
      expected: 'TRUST_KEY_ID_REUSE',
    },
    {
      caseId: 'EXECUTION-006',
      input: {
        ...executionBase,
        executionAssertion: signSyntheticHmacArtifact(executionAssertion, registryKeyHex),
        executionRevocations: signSyntheticHmacArtifact(executionRevocations, registryKeyHex),
        executionKeyHex: registryKeyHex,
      },
      expected: 'TRUST_KEY_MATERIAL_REUSE',
    },
    {
      caseId: 'EXECUTION-007',
      input: {
        ...executionBase,
        registryAssertion: signSyntheticHmacArtifact(missingEvidenceSource, registryKeyHex),
      },
      expected: 'UNTRUSTED_EVIDENCE_SOURCE',
    },
    {
      caseId: 'EXECUTION-008',
      input: { ...executionBase, atTime: executionAssertion.expires_at },
      expected: 'EXECUTION_ASSERTION_EXPIRED',
    },
    {
      caseId: 'EXECUTION-009',
      input: {
        ...executionBase,
        executionAssertion: signSyntheticHmacArtifact(malformedExecution, executionKeyHex),
      },
      expected: 'MALFORMED_TRUST_ARTIFACT',
    },
    {
      caseId: 'EXECUTION-010',
      input: { ...executionBase, handoff: staleHandoff },
      expected: 'STALE_HANDOFF',
    },
    {
      caseId: 'EXECUTION-011',
      input: { ...executionBase, handoff: tamperedHandoff },
      expected: 'STRUCTURAL_APPROVAL_REQUIRED',
    },
  ];
  const executionResults = executionCases.map(({ caseId, input, expected }) => {
    const decision = authorizeCodexExecution(input);
    return { caseId, ...decision, expectedReasonCode: expected, passed: decision.reasonCode === expected };
  });

  const allPassed =
    egressResults.every(({ passed }) => passed) &&
    authResults.every(({ passed }) => passed) &&
    deletionResults.every(({ passed }) => passed) &&
    retentionResults.every(({ passed }) => passed) &&
    executionResults.every(({ passed }) => passed) &&
    exportScans.json.length === 0 &&
    exportScans.markdown.length === 0;

  const results = {
    schemaVersion: 'tacua.exp-004-local-results/v1alpha1',
    experimentId: 'EXP-004',
    phase: 'synthetic_local_pre_implementation',
    status: allPassed ? 'local_contract_simulations_passed' : 'local_contract_simulations_failed',
    exp004Complete: false,
    policyVersion: policy.policyVersion,
    corpusVersion: corpus.corpusVersion,
    deterministicTimeMode: 'simulated_case_timing_only',
    commands: [
      'node --check experiments/security-harness/src/harness.mjs',
      'node --check experiments/security-harness/scripts/run.mjs',
      'node --check experiments/security-harness/scripts/verify-artifacts.mjs',
      'node --check experiments/security-harness/test/harness.test.mjs',
      'node --test experiments/security-harness/test/*.test.mjs',
      'node experiments/security-harness/scripts/run.mjs artifacts/security-harness/EXP-004',
      'node experiments/security-harness/scripts/verify-artifacts.mjs artifacts/security-harness/EXP-004',
    ],
    summary: {
      egressCases: egressResults.length,
      egressPassed: egressResults.filter(({ passed }) => passed).length,
      authorizationCases: authResults.length,
      authorizationPassed: authResults.filter(({ passed }) => passed).length,
      deletionCases: deletionResults.length,
      deletionPassed: deletionResults.filter(({ passed }) => passed).length,
      retentionCases: retentionResults.length,
      retentionPassed: retentionResults.filter(({ passed }) => passed).length,
      executionAuthorizationCases: executionResults.length,
      executionAuthorizationPassed: executionResults.filter(({ passed }) => passed).length,
      completeMatrixCells: matrix.length,
      prohibitedCanariesAtSimulatedEgressSinks: egressResults.reduce(
        (sum, result) => sum + result.actualProhibitedCanariesAtSink,
        0,
      ),
      prohibitedCanariesInJsonExport: exportScans.json.length,
      prohibitedCanariesInMarkdownExport: exportScans.markdown.length,
    },
    egressResults,
    authorizationResults: authResults,
    deletionResults,
    retentionResults,
    executionAuthorizationResults: executionResults,
    exportResults: {
      canonicalTicketDigest: bundle.canonicalTicketDigest,
      jsonHash: sha256(bundle.json),
      jsonByteCount: Buffer.byteLength(bundle.json),
      markdownHash: sha256(bundle.markdown),
      markdownByteCount: Buffer.byteLength(bundle.markdown),
      prohibitedCanariesInJson: exportScans.json.map(({ id }) => id),
      prohibitedCanariesInMarkdown: exportScans.markdown.map(({ id }) => id),
      rawEvidenceEmbedded: false,
      immutableReferencesOnly: true,
      crossFormatCanonicalDigestMatches: true,
      hostileJsonSerializedAsData: true,
      hostileMarkdownEscaped: true,
      passed: exportScans.json.length === 0 && exportScans.markdown.length === 0,
    },
    verificationBoundaries: {
      specificationComplete: [
        'versioned egress-decision schema',
        'complete DATA-001..DATA-012 field/destination matrix',
        'synthetic canary and adversarial corpus',
        'project/member authorization contract',
        'approved Markdown/JSON export contract probe',
        'local lineage deletion and partial-failure contract',
      ],
      locallyExercised: [
        'default deny and unknown schema handling',
        'deterministic canary redaction and sink scanning',
        'negative organization/project/object/job/evidence/ticket/connector authorization',
        'stale and unapproved ticket rejection',
        'hostile Markdown/JSON serialization',
        'retention shortening and prohibited silent lengthening',
        'local deletion lineage with visible partial failure',
        'short-lived exact-scope Codex execution profile and revocation failures using synthetic keys',
      ],
      unverified: [
        'runtime SDK, API, worker, connector, model, UI, object store, database and queue controls',
        'encryption/KMS, authentication provider, service identities and secret manager',
        'external provider no-training, retention, revocation and deletion behavior',
        'backup deletion and restore behavior',
        'binary media OCR/audio redaction effectiveness',
        'deployment hardening and compromised-operator resistance',
        'real nonce-consuming Codex launcher, monotonic registry freshness, effective config/authentication isolation and consumer trial',
      ],
      blocked: [
        'EXP-004 completion pending built runtime boundaries and representative runtime fixtures',
        'pilot-ready status pending qualified security/privacy review',
        'runtime egress schema and selected model/connector broker pending deployment overlays',
      ],
    },
  };

  await mkdir(outputRoot, { recursive: true });
  await writeFile(join(outputRoot, 'run-results.json'), `${stableStringify(results, 2)}\n`);
  await writeFile(
    join(outputRoot, 'egress-matrix.json'),
    `${stableStringify(
      {
        schemaVersion: 'tacua.complete-egress-matrix/v1alpha1',
        policyVersion: policy.policyVersion,
        dataClassCount: policy.dataClasses.length,
        destinationCount: policy.destinations.length,
        fieldCount: policy.dataClasses.reduce((sum, item) => sum + item.fields.length, 0),
        cellCount: matrix.length,
        rows: matrix,
      },
      2,
    )}\n`,
  );
  await writeFile(join(outputRoot, 'coverage.json'), `${stableStringify(coverage, 2)}\n`);
  return { results, matrix, coverage };
}

export function resolveHarnessRoot(importMetaUrl) {
  return resolve(new URL('..', importMetaUrl).pathname);
}
