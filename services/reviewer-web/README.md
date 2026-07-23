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

This direct build is for local development only. A releasable image must be
the exact retained output of the full verifier described in
`services/backend/OPERATIONS.md`; do not rebuild it after verification. The
image is not a standalone public deployment. Use it only behind Tacua's
checked-in same-origin ingress.
