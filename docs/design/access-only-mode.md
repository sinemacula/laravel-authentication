# Access-Only Mode

## Purpose

This note describes the supported bearer-only operating mode for applications that want contextual identity and
principal auth without session tracking or refresh rotation.

## Invariants

- The package can boot and authenticate bearer requests without a `authentication_sessions` table, or any of the
  package's tables.
- `attempt()` counts its attempts in the `rate_limits` table, unless the guard turns its sign-in limits off
  (`rate_limits.sign_in = null`): a deployment that signs in with `attempt()` keeps that table, and the
  `authentication_sessions` and `pending_sign_ins` tables stay empty.
- Access tokens for this mode must be issued with `session = null`, which means the JWT carries no `sid`, and so no
  `auth_time` or `amr` either: a token that names no session and carries one of those fails to parse. `sid` is the one
  access-token claim that may be absent (or `null`); `iss`, `aud`, `client_id`, `sub`, `sub_type` (`person`),
  `principal`, `jti`, `iat` and `exp`, with the `at+jwt` header type, are required as on every access token. With no
  session to bound it, such a token lives exactly the guard's `access_ttl_minutes`.
- The identity model does not need to implement `HasSessions`.
- Bearer auth still rehydrates the identity through the configured provider and resolves the principal through the
  configured resolver.
- `Auth::session()` remains `null`, `SessionAuthenticated` is not emitted, and last-use persistence does not run.
- A session-less token has no session to revoke, so an identity or principal that implements `HasTokensValidAfter` ends
  them instead: the bearer path rejects a token whose `iat` is at or before either one's time
  (`issued_before_cutoff`), read from the models it already loaded, with no extra query. Whole seconds: a token issued
  in the cutoff's own second is rejected too, so a flow that moves the time and then issues a token waits for the
  next second or issues a session. Tokens that name a session are never held to it; revoking the session ends
  them.

## Success Path

- Leave the `authentication_sessions` table out (or empty); keep the `rate_limits` table only for a guard that signs in
  with `attempt()`.
- Do not implement `HasSessions` on the identity model.
- Issue access tokens with `Auth::jwt('api')->issueAccessToken($identity, $principal, $tenant, null)`, where `$tenant`
  is the tenant the principal acts within (carried in `tenant_id`), or `null` for none; a tenant that is not the
  principal's own is refused with an `InvalidArgumentException`.
- On the bearer path, the guard binds identity and principal normally and leaves session unset.
- Query cost stays low because the access-only bearer path only needs the identity read, a recorded "tokens valid
  after" time included.

## Failure / Edge Cases

- A forged non-null `sid` does not cause a best-effort downgrade. The bearer path fails closed even in a deployment that
  has no `authentication_sessions` table.
- This mode is intentionally bearer-only. `JwtTokenService::issueRefreshToken()` still requires a `Session`, and the
  refresh exchange still depends on an `EloquentSession` model plus persisted session state. The session service refuses
  to start a session (`signIn()`, `start()`) for an identity without `HasSessions` with a `LogicException`: every
  session it starts is a persisted one, and the access token it would issue names one this identity can never resolve.
- Its revocation methods work, and are how session-less tokens end early: for an identity without `HasSessions`, or a
  principal whose owner is one, a bulk revocation (`revokeSessions()`, `signOutEverywhere()`, the security-change
  methods, `principalDeactivated()`, `revokePrincipalSessions()`) only moves the scope's "tokens valid after" cutoff and
  reports it; it reads no `authentication_sessions` row and deletes no `pending_sign_ins` row, since no session of such
  an identity can hold either, so neither table needs to exist.
- Guard construction still validates the configured session model: its class, and that it lives on the storage
  connection. The package tolerates a missing table on this path because bearer auth with no `sid` never tries to query
  it.
- Access-token `jti` values are not consulted on the bearer path. Revocation behaviour therefore comes from identity and
  principal rehydration, not from a server-side access-token store.

## Implementation Anchors

- `src/Jwt/JwtTokenService.php`: `issueAccessToken()` and `issueRefreshToken()`.
- `src/Guards/JwtGuard.php`: `resolveBearerToken()`; `src/Guards/BearerAuthentication.php`: `isIssuedAfterCutoff()`.
- `src/SessionRecords/IdentitySessions.php`: `find()`, which finds no session for an identity without `HasSessions`.
- `src/Sessions/RevocationScope.php`: `identity()`, `principal()`, which leave the package's tables alone for an
  identity without `HasSessions`, but for the `identifier_changes` rows an identity's scope cancels when the identity
  implements `HasChangeableIdentifiers` (so such an identity needs that migration).
- `src/Guards/AbstractGuard.php`: `bindAuthenticationLifecycle()`.
- `src/AuthenticationServiceProvider.php`: `createJwtGuard()`; `src/SessionRecords/SessionLookup.php`: `model()`;
  `src/Exceptions/InvalidSessionModelConfigurationException.php`: `validate()`, `offStorage()`.

## Authoritative Tests

- `tests/Integration/Guards/AccessOnlyIntegrationTest.php`
  `testAccessTokenFlowSucceedsWithoutSession`
- `tests/Integration/Guards/AccessOnlyIntegrationTest.php`
  `testForgedSessionHintFailsClosedWithoutSessionsTable`
- `tests/Unit/Jwt/JwtTokenServiceIssueTest.php`
  `testIssueAccessTokenWithoutSessionCarriesNoSessionClaims`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserSkipsSessionWhenNoDidClaimPresent`
- `tests/Performance/JwtGuardQueryBudgetTest.php`
  `testAccessOnlyBearerPathUsesSingleReadAndNoWrites`
- `tests/Integration/Guards/TokensValidAfterIntegrationTest.php`
  `testATimeEndsTheSessionlessTokensIssuedUpToItsSecond`, `testASessionsTokenIsNotHeldToTheTime`
- `tests/Feature/Guards/BearerAuthenticationTest.php`
  `testTheIdentitysTimeLimitsASessionlessToken`, `testThePrincipalsTimeLimitsASessionlessToken`,
  `testThePrincipalsTimeLimitsATokenWhoseIdentityRecordsNone`
- `tests/Integration/Guards/TokensValidAfterIntegrationTest.php`
  `testThePrincipalsTimeLimitsATokenWhoseIdentityRecordsNone`
- `tests/Integration/Sessions/RevocationScopeTest.php`
  `testAnAccessOnlyIdentitysRevocationsOnlyMoveItsCutoff`, `testAPrincipalOfAnAccessOnlyIdentityOnlyMovesItsCutoff`
- `tests/Performance/TokensValidAfterQueryBudgetTest.php`
  `testAnAcceptedTokenCostsOneRead`, `testARejectedTokenCostsOneRead`

## Change Triggers

Update this note when any of the following change:

- the rule that access-only tokens carry no `sid`, `auth_time` or `amr`
- whether bearer auth can still succeed without `HasSessions`
- whether access-only bearer auth remains free of session writes
- whether refresh becomes supported without persisted session state
- which package tables `attempt()` or bearer auth need
- how a "tokens valid after" time limits session-less tokens
- whether guard construction still validates the configured session model class up front
