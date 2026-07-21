# Security Policy

## Supported versions

Tacua is pre-release software and currently has no supported versions or security-maintenance guarantee.

| Version | Supported |
| --- | --- |
| Pre-release development snapshots | No |

Do not use Tacua with production or sensitive data unless you have independently assessed and accepted the risk.

## Reporting a vulnerability

Use GitHub private vulnerability reporting: open this repository's **Security** tab and choose **Report a vulnerability**. Do not disclose suspected vulnerabilities in a public issue, discussion, or pull request.

If that button is unavailable, open a public issue containing only the sentence “Private security reporting is unavailable” and no vulnerability, reproduction, environment, or evidence details. A maintainer will repair the private channel before asking for sensitive information.

Include, where safe:

- the affected revision or component;
- impact and realistic attack conditions;
- minimal reproduction steps or a proof of concept; and
- suggested mitigations, if known.

Use sanitized evidence. Do not include real app recordings, credentials, access tokens, personal data, private source code, or production telemetry. If sensitive material is essential, first ask through the private report how to transfer it safely.

Reports are handled on a best-effort basis while the project is pre-release. Maintainers will coordinate validation, remediation, and disclosure with the reporter, but no response or fix timeline is currently guaranteed.

## Self-hosting responsibilities

Operators are responsible for securing their deployment, secrets, storage, network exposure, backups, retention settings, model-provider credentials, and updates. A default configuration is not a substitute for an environment-specific security review.
