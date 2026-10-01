# Security controls and limitations

The published application is the patched Squeak implementation. Its controls address the input validation, session integrity, and authorization issues explored during the original coursework.

| Area | Implemented protection |
| --- | --- |
| Login queries | Validated username and string password; password checked against stored scrypt hash |
| Password storage | Random salt and scrypt-derived hash; timing-safe comparison |
| Cookie integrity | HMAC-SHA256 signature checked before use |
| Session identity | Database lookup binds validated ID to username |
| Session deletion | Validated session ID passed to `deleteOne` |
| Private inbox | Recipient comes from authenticated identity |
| CSRF | Signed guest token and session-bound token on write routes |
| Cookies / transport | HTTPS; session cookie uses Secure, HttpOnly, SameSite=Strict |
| Input and output | Scalar validation, 20 KB request limit, validated recipients, 280-character posts, escaped inline JSON and text rendering |

## Publication preparation

- Removed hard-coded cloud database credentials and the shared signing-secret fallback from application source.
- Added ignored local `.env` configuration and a safe template and loopback defaults.
- Required TLS and successful MongoDB initialization before the patched server listens.
- Made malformed signature lengths and malformed cookie encoding fail safely in the patched version.
- Escaped `<` in inline JSON to prevent message content from closing the template's script element.
- Excluded the local unpatched baseline, existing keys, certificates, reports, screenshots, dependency trees, and packaged copies from Git. These local artifacts may still contain sensitive material and must not be uploaded separately.

## Remaining limitations

The patched version is not a complete production security implementation. It has no login rate limiting, account recovery, email verification, pagination, security-header policy, or structured audit logging. Scrypt is synchronous and can block the event loop under load. Expired sessions are checked on access rather than removed by a MongoDB TTL index; session expiration refresh does not refresh the browser's session-cookie lifetime. The username directory is publicly accessible, and `all` is a reserved recipient value but is not rejected as an account name.

Express 4 does not automatically forward rejected promises from async route handlers; comprehensive async error handling and duplicate-signup race handling remain follow-up work. Dependency vulnerability auditing and end-to-end validation with MongoDB are required before any deployment.

## Credential response

The original folder contained a cloud database username/password and a TLS private key. Rotate or delete the database credential in the database provider's console, review access logs as appropriate, and generate fresh local TLS material. Ignoring those files protects future commits but does not revoke existing secrets. If an earlier copy was published elsewhere, remove secrets from that history as well.
