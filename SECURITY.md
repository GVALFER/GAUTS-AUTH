# Security Policy

## Supported versions

Security fixes are provided for the latest published minor version.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No |

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

## Signed session cache

The optional browser cache is disabled when omitted. When configured, it is accepted only for `GET` and `HEAD` requests and is signed with HMAC-SHA-256 using an application-provided secret of at least 32 bytes.

The cache is bound to the opaque session token, its own expiry, the authoritative session expiry, and the configured client fields. Invalid cache data never authenticates a request; it causes normal database validation.

Cookie caching introduces a bounded consistency window. A session revoked on another device, or selected account or relation access changed in the database, may remain readable until the cache TTL expires. Unsafe methods, renewal, logout, WebSockets, and direct core calls always validate through the database. Applications requiring immediate cross-device read revocation must leave the cache disabled or provide shared server-side enforcement outside this package.

Keep `AUTH_SECRET` in the API environment. Do not expose it to browser code or share it with a frontend merely to inspect the renewal timestamp. The timestamp is intentionally untrusted and never authenticates or renews a session by itself.

## Session lifetime

Sliding renewal is limited by `session.maxLifetime`, which defaults to 30 days from the original login. The maximum expiry is derived from the immutable session `created_at` value and enforced by the core during resolution and renewal. Browser cookies and cached session data never outlive the authoritative session expiry.

Activity and possession of the session token cannot extend this absolute limit. After it is reached, the user must authenticate again and receive a new session token.

## Social authentication

Configured providers use OAuth Authorization Code with PKCE `S256`. A cryptographically random state value and PKCE verifier are bound to a signed, HttpOnly transaction cookie that expires after 10 minutes. The package accepts only verified provider email addresses and stores only the normalized provider name and stable provider account ID.

Provider access tokens, refresh tokens, and raw profiles are never persisted or exposed to registration callbacks. Success, error, callback, and optional registration URLs are fixed startup configuration; request parameters cannot select redirect targets.

The consuming application must protect custom social registration endpoints with its normal CSRF, host, origin, rate-limit, and validation policies. `AUTH_SECRET` must remain server-only and contain at least 32 high-entropy bytes.
