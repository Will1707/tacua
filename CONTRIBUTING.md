# Contributing to Tacua

Tacua is an early, pre-release project. Contributions are welcome, but interfaces, architecture, and contribution policy may change while the product is being de-risked.

## Before you start

- Open an issue before a large feature, architectural change, new dependency, or compatibility break so scope can be agreed before substantial work begins.
- Keep pull requests focused. Explain the problem, the chosen approach, and any trade-offs.
- Add or update tests and documentation appropriate to the change. Use the validation instructions documented by the affected package; do not claim checks that were not run.
- Preserve Apache-2.0-compatible licensing. Do not submit code, media, or other material that you do not have permission to contribute.

## Privacy and self-hosting

Tacua handles recordings and diagnostic evidence from mobile apps. Treat that data as sensitive.

- Use synthetic or explicitly sanitized fixtures. Never commit real recordings, credentials, access tokens, private source code, personal data, stable device identifiers, or production telemetry.
- Document any new data collection, network destination, external service, retention behavior, deletion behavior, or secret. New external egress must be explicit and operator-controlled.
- Keep the self-hosted path functional. A feature must not silently require a hosted Tacua service.
- Changes to capture, SDK instrumentation, storage, AI-provider integrations, authentication, or authorization must describe their privacy and security impact in the pull request.

If a report may expose a vulnerability or sensitive data, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Developer Certificate of Origin

The project's provisional contribution mechanism is the [Developer Certificate of Origin 1.1](https://developercertificate.org/) (DCO), with no Contributor License Agreement (CLA).

Every commit must include a `Signed-off-by: Name <email>` trailer using an identity you are authorized to use. The sign-off certifies that you have the right to submit the contribution under the project's license. You retain copyright in your contribution; accepted contributions are licensed under Apache-2.0 under the terms in [LICENSE](LICENSE).

Maintainers may ask contributors to repair missing sign-offs before merging. Any future change to this mechanism will be documented before it applies to new contributions.

## Pull requests

A pull request should:

- link the relevant issue or explain why no issue is needed;
- summarize user-visible and operational effects;
- identify validation performed and any validation still outstanding;
- call out migrations, compatibility changes, and privacy or security impact; and
- contain only commits intended for inclusion, each with a DCO sign-off.

By participating, you agree to follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
