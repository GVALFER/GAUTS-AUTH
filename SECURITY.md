# Security Policy

## Supported versions

Security fixes are provided for the latest published minor version.

| Version | Supported |
| --- | --- |
| `0.2.x` | Yes |
| `< 0.2` | No |

## Reporting a vulnerability

Do not report suspected vulnerabilities through public GitHub issues or discussions.

Use [GitHub private vulnerability reporting](https://github.com/GVALFER/GAUTS-AUTH/security/advisories/new) and include:

- the affected package version;
- a clear description of the impact;
- reproduction steps or a minimal proof of concept;
- any known mitigations;
- whether the report may be disclosed after a fix is available.

Reports are reviewed privately. A public advisory and patched release will be prepared when the issue is confirmed.

## Scope

Security reports may cover the password service, session core, database adapters, framework adapters, published package contents, or dependency supply chain.

Application-specific authorization, rate limiting, CSRF, CORS, proxy trust, deployment, and database access policies remain the consuming application's responsibility unless the vulnerability is caused by package behavior.
