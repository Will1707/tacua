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
