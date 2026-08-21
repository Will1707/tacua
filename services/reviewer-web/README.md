# Reviewer web container

This image serves only a validated Expo web export. It has no backend
configuration, administrator credential, state, source checkout, Docker socket,
writeable mount, or network authority beyond the internal Compose network.

Prepare and verify the ignored release directory before building:

```sh
npm --prefix apps/reviewer ci --ignore-scripts --no-audit --no-fund
node .github/scripts/generate-reviewer-third-party-notices.mjs
npm --prefix apps/reviewer run export:web -- --output-dir dist --clear
node .github/scripts/validate-reviewer-web-image-inputs.mjs
docker build -f services/reviewer-web/Dockerfile -t tacua-reviewer-web:local .
```

The export may be generated under either the ordinary `022` umask
(`0755` directories and `0644` files) or an owner-private `077` umask
(`0700` directories and `0600` files). The closed Docker boundary copies only
the validated fixed directory shape and normalizes it to root-owned mode
`0555` directories and mode `0444` static files; it never copies deployment
credentials, configuration, or state. The same boundary separately validates
the server, project notices, license, and generated third-party notice as
bounded single-link regular files before the build runs.

The validator snapshots the repository ancestry, every copied input, and the
complete export tree, opens and reads every accepted file as the invoking
process, then rechecks their identities and modes after all content reads.
Validation and a direct local `docker build` are still separate
processes, so run them only in a quiescent, access-controlled checkout; release
automation must retain the verifier's exact image rather than rebuilding it.

This direct build is for local development only. A releasable image must be
the exact retained output of the full verifier described in
`services/backend/OPERATIONS.md`; do not rebuild it after verification. The
image is not a standalone public deployment. Use it only behind Tacua's
checked-in same-origin ingress.
