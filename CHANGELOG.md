# Changelog

## 0.1.0 (2026-11-21)

First release. Stateless contextual authentication for Laravel that tells apart the identity that signed in, the
principal it acts as and the session it signed in on.

### Features

* `Auth::identity()`, `Auth::principal()`, `Auth::tenant()` and `Auth::session()` through Laravel's own `Auth` facade, middleware and events
* a JWT guard whose access tokens carry RFC 9068 claims, signed with HMAC keys selected by key id
* a session for every sign-in, with idle and absolute lifetimes, and pending sessions that become active once their requirements are met
* refresh token rotation per application, with replay detection that revokes the session
* sign-in by password, one-time code, passkey, API key and OAuth client credentials with scopes
* a session service with one plain-value method per action, and request helpers that feed it
* per-guard policy, tenant authentication policies and switching the active tenant within a session
* password policy, password reset and identifier change flows
* rate limiting of sign-in, refresh, client credentials, password reset, identifier change and code requests
* session proofs and provenance: what a session proved, when, and the connection and client it came through
* seams for multi-factor and single sign-on packages: factor changes, freshness, external sign-in and re-authentication through a link, and assurance evidence
* revocation of sessions by identity, principal, tenant, link or factor
* lifecycle events with queue-safe snapshots, and an authentication context of plain values
* one storage setting for every table's connection, and per-request state isolated under Octane and queues
* a configuration check that other packages can extend, testing helpers and translatable messages
