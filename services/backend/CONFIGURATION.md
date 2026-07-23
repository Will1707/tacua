# Sealing a self-hosted backend configuration

Tacua's backend config is public deployment metadata. Keep administrator
secrets in a separate mounted secret file; never put credentials, tokens,
cookies, or private keys in the template. The compiler rejects known secret
field names and has no argument or code path for reading a secret.

Start from [`config.template.example.json`](config.template.example.json). The
four `__TACUA_DERIVE_SHA256__` values are mandatory markers, not placeholders
to fill by hand. The dependency-free compiler derives and seals:

- `build_identity.transport_configuration_digest` from the normalized backend
  origin and frozen transport policy;
- the SDK protocol `build_identity.build_identity_digest`;
- `approved_handoff.build_identity.sdk.configuration_digest` from that same
  transport pin; and
- the approved-handoff `build_identity_digest`.

The same invocation can project the deployment pin into a secret-free,
canonical SDK profile. The profile contains the exact registered SDK
`build_identity`, normalized backend origin and transport digest, and the static
capture-scope policy: organization/project/application/build pins, required
consent contract, and raw/derived retention. It contains no launch code,
credential, administrator secret, or provider key.

The current pilot configuration pins exactly one project, application, tested
build, reviewer identity, and administrator credential per deployment. Run a
separately pinned deployment for another scope. This is an implementation
limit of the current backend, not a change to the [product boundary](../../docs/PRODUCT.md),
which permits future multiple projects and members.

From the repository root, compile a template to a mounted config file:

```sh
chmod go-w . services services/backend
test ! -L services/backend/local
install -d -m 0700 services/backend/local
cp services/backend/config.template.example.json \
  services/backend/local/config.template.json

# Edit only the measured/operator-owned values, then seal the result.
${EDITOR:-vi} services/backend/local/config.template.json
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.config_tool \
  services/backend/local/config.template.json \
  --output services/backend/local/config.json \
  --sdk-profile-output services/backend/local/tacua-sdk-profile.json
```

The output write is atomic and the file is mode `0644` because it must contain
no secrets. Compilation runs the generated document through the same public
configuration parser used during backend startup. It does not read an admin
secret, create the configured state directory, open SQLite, or contact a
network service.

Use check mode in CI or before restarting a deployment:

```sh
# Validate and seal in memory without writing anything.
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.config_tool \
  services/backend/local/config.template.json --check

# Also require the existing output to match the template byte for byte.
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.config_tool \
  services/backend/local/config.template.json \
  --output services/backend/local/config.json \
  --sdk-profile-output services/backend/local/tacua-sdk-profile.json \
  --check
```

Without `--output`, normal mode writes the sealed public JSON to standard
output. `--sdk-profile-output` requires `--output`; every path must be distinct.
Both generated files use atomic, durable mode-`0644` publication. `--check`
never writes and requires both existing artifacts to match their template byte
for byte.

The SDK profile is exactly one canonical JSON line followed by LF and carries a
`profile_digest` over every other field. Commit or transfer it as public build
input, then point the `@tacua/mobile-sdk` Expo config plugin at its path. The
plugin independently validates the profile and measured build pins before
embedding it. [`sdk-profile.example.json`](sdk-profile.example.json) is the
exact output produced from the checked-in example template.

## Seal a signed iOS QA build without a digest cycle

For iOS, `approved_handoff.build_identity.mobile.native_binary_digest` means
the SHA-256 digest of the final operator-controlled, code-signed main Mach-O
executable named by `CFBundleExecutable`. For a local build, measure the exact
`.app` that will be installed. For TestFlight, measure the executable inside
the exact signed archive submitted to App Store Connect. This is a
producer-artifact identity: Apple may re-sign, encrypt, thin, or otherwise
process a TestFlight artifact, so the digest does not attest the post-processed
or installed TestFlight bytes. It is not a digest of the unsigned build
product, `.app` directory metadata, an ad-hoc zip, or an IPA container. The
static Tacua SDK is linked into this executable. The source revision and sealed
SDK profile separately record the intended JavaScript/resources source and
deployment configuration.

The digest cannot exist until the signed app exists, while the signed app must
already contain the final SDK profile. Use this two-pass procedure; do not put a
placeholder digest into a live backend:

1. Fill every measured template value except the native binary digest, retain
   all four derive markers, and use a clearly non-live digest value only for
   this first compilation of `config.json` plus `tacua-sdk-profile.json`.
   Never deploy the first-pass config.
2. Save an exact copy of that profile, then build and code-sign the QA `.app`
   from the clean source revision using that profile. Do not mutate or re-sign
   the app after measurement.
3. Verify the app's signature and hash its main executable:

   ```bash
   set -euo pipefail
   qa_app='/absolute/path/to/TacuaQA.app'
   test -d "$qa_app"
   test ! -L "$qa_app"
   /usr/bin/codesign --verify --deep --strict --verbose=2 "$qa_app"
   bundle_executable="$(
     /usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' \
       "$qa_app/Info.plist"
   )"
   case "$bundle_executable" in
     ''|.|..|*/*) echo 'invalid CFBundleExecutable' >&2; exit 1 ;;
   esac
   native_executable="$qa_app/$bundle_executable"
   test -f "$native_executable"
   test ! -L "$native_executable"
   native_binary_sha256="$(
     /usr/bin/shasum -a 256 "$native_executable"
   )"
   native_binary_sha256="${native_binary_sha256%% *}"
   case "$native_binary_sha256" in
     *[!0-9a-f]*|'') echo 'invalid SHA-256 result' >&2; exit 1 ;;
   esac
   test "${#native_binary_sha256}" -eq 64
   ```

4. Replace only
   `approved_handoff.build_identity.mobile.native_binary_digest` in the
   template with `sha256:` followed by `native_binary_sha256`. Re-run the
   compiler. It must reseal the approved-handoff build identity and backend
   config.
5. Compare the regenerated SDK profile byte for byte with the saved first-pass
   profile using `cmp -s`. A difference means another build input changed:
   discard the measured app, resolve the mismatch, and repeat from step 1.
6. Deploy the final backend config together with that unchanged SDK profile,
   and install only the measured signed app. Any re-sign, rebuild, profile
   change, source change, or backend-origin change requires a new measurement
   and an empty deployment pin.

The main-executable convention is deterministic for operator-controlled local
and pre-submission TestFlight producer artifacts and avoids treating
archive/zip timestamps as build identity. It does not claim to attest Apple's
distribution transformations or every resource independently; the clean source
revision and byte-identical sealed profile remain mandatory parts of the same
build identity.

## Values the operator must supply

The compiler cannot measure or safely infer these values:

- the native binary digest and mobile source revision;
- the mobile repository identifier;
- the installed SDK package version and source revision;
- backend image, deployment, and source-repository identity when marked
  available (otherwise retain the contract's explicit unavailable form);
- the public HTTPS backend origin, organization/project/application/build
  identifiers, versions, distribution, and state/listener settings;
- the exact authority repository allow-list and registry revision; and
- retention periods and operational byte/time limits.

The SDK and approved-handoff build projections must describe the same measured
build. Authority must cover every named source repository. Any inconsistency,
unknown key, duplicate key, float, unsafe integer, non-NFC string, stale digest
in place of a derive marker, invalid contract value, or cross-artifact mismatch
fails closed without producing a config.

After generating `config.json`, create the separate administrator secret and
start Compose:

```sh
PYTHONPATH=services/backend/src python3 -B -m tacua_backend.operator_tool \
  create-admin-secret \
  --destination services/backend/local/admin-secret
docker compose -f services/backend/compose.yaml up --build
```

Compose implements file-backed secrets as read-only bind mounts and cannot
remap their owner. The exact mode `0444` lets the fixed non-root container read
the mounted file; the enclosing, operator-owned mode-`0700` directory prevents
other host users from traversing to it. The repository-side parent must also
be protected so the private directory cannot be replaced between preflight and
Compose. The setup removes group/world write from the checkout, `services`, and
`services/backend`; preflight walks the complete resolved ancestor chain and
allows writable shared ancestors only when sticky ownership protects entries
(for example, root-owned `/tmp`). The creation command uses exclusive,
no-follow publication and never prints or hashes the generated secret. Never
move or copy this mode-`0444` file outside that private directory. Production
preflight validates the complete path boundary.

Before production startup, validate the resolved digest-pinned Compose model,
host file permissions, and public deployment metadata with the preflight in
[OPERATIONS.md](OPERATIONS.md). Config and administrator secret are backed up
and restored only as one exact recovery set with their state; changing either
against existing state fails closed or invalidates outstanding capabilities.
