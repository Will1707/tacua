<!-- SPDX-License-Identifier: Apache-2.0 -->

# Physical-pilot terminal operation receipt

[`finalize_pilot_operation.py`](scripts/finalize_pilot_operation.py) closes one
local physical-pilot operation with an immutable, canonical JSON receipt. It is
a dependency-free host tool and does not contact a device or backend.

The receipt gives an operation exactly one explicit terminal state:
`succeeded` or `failed`. A successful receipt cannot be emitted unless the
caller supplies all of the following:

- a final validation result whose state is `passed`;
- a positive `attested_complete` client-cleanup attestation;
- a helper outcome of `attested_absent`, or `not_applicable` with a stable
  reason code when no temporary helper was used; and
- at least one evidence file, with every bound file verified as a stable,
  current-user-owned, owner-private, regular file with exactly one hard link.

A failed receipt requires one stable failure stage and code. Failed validation,
incomplete cleanup, or an unverified helper outcome can therefore be recorded
without being confused with success.

## Trust boundary

This is a **local host attestation**, not server-signed proof. SHA-256 bindings
and the receipt seal detect changes relative to the caller-supplied input and
evidence bytes. They do not independently prove who produced those files, that
an administrator endpoint was authenticated, that a physical device performed
the operation, or that backend state remains durable. The current local user
controls both the input attestations and the private evidence directory.

The SDK/backend completion receipt may be included as an evidence file, but in
this contract it is only bound by its raw-file digest. Tacua does not currently
expose a server API that signs or anchors this top-level operation-receipt
digest. Adding such an endpoint, its key lifecycle, and independent
verification is a separate future security change; the local finalizer does
not imitate server proof with a host-held secret.

The terminal receipt deliberately contains no filesystem paths or evidence
content. It contains only caller-chosen evidence names and roles, media types,
byte sizes, SHA-256 digests, version strings, closed attestation fields, and its
own canonical SHA-256 seal.

## Finalization input

Create an owner-private, single-link input file. Every evidence path must be an
absolute path to an owner-private, single-link regular file. Version strings
bind the exact validation harness, narration source, and other relevant source
revisions without placing source paths in the receipt.

```json
{
  "client_cleanup": {
    "attestation_version": "tacua.client-cleanup@1.0.0",
    "attested_at": "2026-08-03T12:29:55Z",
    "reason_code": null,
    "state": "attested_complete"
  },
  "completed_at": "2026-08-03T12:30:00Z",
  "contract_version": "tacua.pilot-operation-finalization-input@1.0.0",
  "evidence": [
    {
      "media_type": "application/json",
      "name": "capture_result",
      "path": "/owner-private/operation/capture-filtered.json",
      "role": "capture_validation"
    },
    {
      "media_type": "application/json",
      "name": "session_detail",
      "path": "/owner-private/operation/session-detail.json",
      "role": "backend_receipt"
    }
  ],
  "failure": null,
  "helper_uninstall": {
    "attestation_version": "tacua.helper-uninstall@1.0.0",
    "attested_at": "2026-08-03T12:29:58Z",
    "reason_code": null,
    "state": "attested_absent"
  },
  "narration": {
    "version": "pilot-narration-v1"
  },
  "operation_id": "pilot_operation_001",
  "sources": [
    {
      "source_id": "mobile_sdk",
      "version": "0.1.0"
    },
    {
      "source_id": "pilot_harness",
      "version": "1.4.0"
    }
  ],
  "terminal_state": "succeeded",
  "validation": {
    "reason_code": null,
    "state": "passed",
    "version": "tacua.filtered-xcuitest@1.4.0"
  }
}
```

The fixed attestation states are:

| Field | Positive success states | Other terminal states |
| --- | --- | --- |
| `validation.state` | `passed` | `failed` |
| `client_cleanup.state` | `attested_complete` | `incomplete`, `not_attested` |
| `helper_uninstall.state` | `attested_absent`, `not_applicable` | `incomplete`, `not_attested` |

`not_applicable` is positive only when it includes an attestation timestamp and
the exact reason `HELPERS_NOT_USED`. It must never be used when a helper was
installed. Negative and unavailable states require a stable reason code;
positive completed/absent states do not accept one.

## Operator sequence

1. Stop capture, narration playback, and UI-test processes.
2. Obtain and validate the final backend/session evidence.
3. Clear volatile launch material and complete client cleanup.
4. Uninstall temporary automation helpers and verify their absence. If the
   operation never used helpers, attest `not_applicable` explicitly.
5. Write the finalization input and all evidence under an owner-private
   directory. Use owner-only permissions and retain the input alongside the
   evidence so verification can re-resolve its paths.
6. Finalize once:

   ```sh
   python3 -B experiments/ios-capture-spike/scripts/finalize_pilot_operation.py \
     finalize \
     --input /owner-private/operation/finalization-input.json \
     --output /owner-private/operation/operation-receipt.json
   ```

7. Verify before treating the operation as closed:

   ```sh
   python3 -B experiments/ios-capture-spike/scripts/finalize_pilot_operation.py \
     verify \
     --input /owner-private/operation/finalization-input.json \
     --receipt /owner-private/operation/operation-receipt.json
   ```

Finalization writes and flushes a mode-`0600` temporary file in the destination
directory, publishes that complete inode under the final name with a
no-replace link, flushes the directory, removes the temporary name, and flushes
the directory again. An existing receipt is never overwritten, including if a
non-cooperating local writer wins the final-name race. Both the input and
receipt remain subject to the pilot's private seven-day diagnostics retention
policy.

If the process stops after publishing the final name but before removing its
temporary name, the complete receipt temporarily has two hard links. An
identical `finalize` retry or `verify` may finish that publication only when
there is exactly one correctly named, mode-`0600`, current-user-owned temporary
link to the same inode and its canonical bytes equal the reconstructed receipt.
The recovery removes only that temporary name and flushes the directory. Any
other multi-link state fails closed. This exception applies only to the
finalizer's receipt inode; caller-supplied evidence always requires exactly one
hard link.

Verification revalidates input safety, rehashes every evidence path, validates
canonical receipt bytes and the receipt seal, and requires exact equality with
the reconstructed receipt. A valid failed receipt verifies successfully while
remaining visibly and structurally `failed`.
