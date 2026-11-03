# Fail-Closed `principal` / `sid`

## Purpose

This note records the rule that `principal` and `sid` are treated as commitments, not best-effort hints. If a token
claims a specific principal or session and the runtime cannot prove that claim, authentication fails.

## Invariants

- A present `principal` must resolve to that exact principal identifier. The same check verifies a principal pinned on
  `attempt()`, which must also come back as the same class and be owned by the authenticated identity: its
  `getIdentity()`, read from the write connection and from the principal's stored key rather than a relation the
  resolver set (lazily, even when the principal was hydrated with lazy loading prevented), must be that identity's class
  and auth identifier, so a resolver whose hinted lookup is not scoped to the identity cannot bind another identity's
  principal. An owner that cannot be read fails closed.
- A present bearer `sid` must resolve to a real, unrevoked session owned by the resolved identity that has not ended. A
  session with `revoked_at` set, or past its idle or absolute deadline (or without one), is rejected like a missing one,
  with its own reason (`session_revoked`, `session_expired`; a session of another guard `session_guard_mismatch`, a
  missing one `session_unknown`), so revoking or ending a session ends its access tokens at once; the check reads the
  row the lookup already loaded, with no extra query, and applies no JWT leeway, so an access token cannot outlive its
  session. Any stored `revoked_at` counts, so a custom model using `ActsAsSession` without a `datetime` cast on the
  column is rejected too, and a session loaded without one of its state columns throws a `LogicException` instead of
  being read as not revoked. The same lookup verifies a session pinned on `attempt()`, which must also come back as the
  same class.
- A bearer `sid` is accepted only in the tenant and for the principal the session records, in that order: the token's
  `tenant_id` (absent for none) must be the session's `tenant_id`, its active tenant, else `session_tenant_mismatch`;
  the session's `principal_type` and `principal_id` must name the token's principal (a session that records none fails
  closed), else `session_principal_mismatch`; and the token's `iat` must not be before the second of the session's last
  context change (`switched_at`: a switch of principal or active tenant, a return to pending, an activation), else
  `session_switched`. A switch from A to B ends A's tokens at once, and a switch back to A does not revive the A tokens
  issued before it; the switch's own tokens are issued in its second, so they pass, except after a second change in that
  same second, whose floor is one second later (`SwitchFloor::after()`): its tokens are refused until the client
  refreshes after it, and no earlier token is ever revived. The active tenant must then still resolve and be active
  (`tenant_inactive`): the principal's own, already checked, is not read again, and any other is resolved through the
  `TenantResolver`, with no access contract asked. A session pinned on `attempt()` must record the principal being
  bound, else `session_mismatch`, and acts in the tenant it records, held to `TenantAccess` and its activity. The checks
  read the row already loaded, with no query beyond the resolver's for another tenant, and a session loaded without
  `tenant_id` or `switched_at` throws a `LogicException` rather than reading as acting in none or never switched.
- Refresh is stricter than bearer auth: refresh always requires a valid `sid`, because refresh is session-backed.
- A `sid` is checked against the session model's key format before any query; one that cannot be a key fails closed as
  an unresolved session, and a database error on a well-formed `sid` propagates instead of reading as a missing session.
- Unsupported or transient identifiers stringify to `null` and therefore fail matching rather than being tolerated.
- Failure attribution should still point at the already resolved identity when `principal` or `sid` rejection happens
  late in the bearer flow.
- `principal`, `sid`, and active-state checks run live on every request; nothing is cached across requests.
- The identity, principal, tenant, and session reads behind those checks go to the write connection, so a lagging read
  replica cannot satisfy a `principal` or `sid`, or an activity check, the primary no longer recognises. The identity,
  principal, and session lookups run inside `WriteConnection::during()`, which pins their model's connection and every
  connection a model resolves while they run, so relations they eager-load (a `$with` tenant, say) come from the writer
  too, not only the lookup's own query, even on another connection; so does each `CanBeActive::isActive()` check, the
  tenant read, and a session's revocation and deadline reads, whether or not the subject is an Eloquent model. The
  identity's `sessions()` relation is built inside the identity's window, so a relation that queries while it is built
  reads the writer as well.

## Success Path

- An access token must carry `principal`: one without it fails to parse, so the bearer path never falls back to the
  resolver's default principal. A refresh token may omit `principal`, in which case refresh uses the default principal
  policy.
- Issuing enforces the same claims: `issueAccessToken()` and `issueRefreshToken()` throw an `InvalidArgumentException`
  instead of minting a token with an empty `sub`, `principal`, `sid`, or `jti` (an unsaved model or a non-scalar
  identifier), so a token that could never authenticate, or would silently drop its session or principal, is never
  issued. An access token for an Eloquent session with no key, or whose row is gone, is refused earlier, with a
  `LogicException`, by the issuance guard it writes first.
- If no bearer `sid` is present, auth can still succeed with `session = null`.
- If `principal` is present and the resolver returns the exact matching principal, auth continues normally.
- If refresh carries `principal`, the same exact-match rule is applied before the rotated pair is issued.

## Failure / Edge Cases

- The default resolver may fall through from a hinted miss to the 2D or 3D default principal path. The guard and the
  refresh exchange explicitly prevent that fallback from becoming an auth downgrade by re-checking the resolved
  identifier against the hinted `principal`.
- Identities may implement `ResolvesHintedPrincipal` to short-circuit the hinted lookup, but a `null` / non-Principal
  result still falls through to the existing default resolver path and is therefore subject to the same fail-closed
  `principal` re-check.
- A resolver that returns an unsaved principal with a `null` identifier is rejected for the same reason.
- On the bearer path, `sid` resolution is identity-scoped through `HasSessions`; a token that claims a session against
  an identity with no session capability fails closed instead of silently binding no session, and a `sessions()`
  relation over a model that is not an `EloquentSession` throws a `LogicException` before it is queried.
- On the refresh path, `sid` resolution is global through the configured session model, and the session's owner is
  reloaded through the guard's identity provider (see `guard-bound-tokens.md`).
- When bearer auth rejects a token after the identity has already been loaded, the `AuthenticationFailed` event still
  carries that resolved identity (and the principal and session, once found) for attribution, and the `sid` the token
  named.

## Implementation Anchors

- `src/Guards/BearerAuthentication.php`: `authenticate()`, `admitAs()` (the exact `principal` match), `onSession()` and
  `principalRefusal()`; `src/SessionRecords/OwnedSession.php`: `refusal()`, `actsAs()` and `isIssuedSinceSwitch()`,
  shared with the `attempt()` session pin.
- `src/SessionRecords/IdentitySessions.php`: `find()`, the identity-scoped session lookup behind a bearer `sid`, a
  session pinned on `attempt()` and the session service's `revokeSession()`.
- `src/Guards/Concerns/VerifiesPinnedContext.php`: `resolvePinnedPrincipal()`, `resolvePinnedSession()` and
  `resolveSessionFromHint()`, the pinned-context checks in `attempt()`.
- `src/Jwt/RefreshTokenExchange.php`: `extractRefreshClaims()`; `src/Jwt/RefreshJudgment.php`: `classify()`;
  `src/Jwt/RefreshAdmission.php`: `principal()`; the session is found by `src/SessionRecords/SessionLookup.php`'s
  `find()`.
- `src/Support/IdentifierCoercion.php`: `stringify()` and `matches()`, the exact-match rule behind the bearer and
  refresh `principal` checks.
- `src/Jwt/Enums/TokenType.php`: `requiredClaims()`, enforced by `JwtTokenService::parse()`.
- `src/SessionRecords/SessionKeyShape.php`: `matches()`, the `sid` shape check shared by the bearer and refresh paths.
- `src/SessionRecords/SessionDeadlines.php`: `hasEnded()`, the one deadline rule the bearer path, pins, refresh, and
  issuance share.
- `src/Database/WriteConnection.php`: `query()` and `during()`, which pin the identity, principal, tenant, and session
  reads to the write connection; `src/Database/PinningConnectionResolver.php` carries the pin to every connection a
  model resolves inside `during()`.
- `src/Resolvers/DefaultPrincipalResolver.php`: default resolver behaviour that the guard hardens with explicit
  `principal` matching, including the optional `ResolvesHintedPrincipal` shortcut ahead of the generic `HasPrincipals`
  lookup.
- `src/Contracts/ResolvesHintedPrincipal.php`: optional 3D optimisation seam for hinted principal hydration.
- `src/AuthenticationServiceProvider.php` and `src/Guards/JwtGuard.php`: resolver-rebind wiring so bearer and refresh
  stay on the same principal policy.

## Authoritative Tests

- `tests/Feature/Tenancy/ActiveTenantTest.php` (the active tenant on every request, refresh and deactivation)
- `tests/Integration/Guards/BearerAuthenticationTest.php` `testATokenTheRowsRejectIsReportedOnceWithItsReason`,
  `testSwitchingAwayAndBackDoesNotReviveEarlierTokens`
- `tests/Feature/Sessions/SessionSwitchTest.php` `testATenantOnlySwitchMovesTheSessionToAnotherTenant`,
  `testSwitchingBackToATenantDoesNotRestoreItsOldTokens`, `testTwoSwitchesInOneSecondRefuseEveryEarlierToken`
- `tests/Feature/SessionRecords/OwnedSessionTest.php` `testASessionActsOnlyInTheTenantItRecords`

- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserAttributesTheFailureToTheResolvedIdentityWhenPidHintRejectsToken`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserRejectsTokenWithoutPrincipalClaimInsteadOfUsingTheDefault`
- `tests/Unit/Jwt/JwtTokenServiceTest.php`
  `testParseRejectsATokenMissingARequiredClaim`
- `tests/Unit/Jwt/JwtTokenServiceIssueTest.php`
  `testIssueAccessTokenRefusesAPrincipalWithoutUsableIdentifier`
- `tests/Unit/Jwt/JwtTokenServiceIssueTest.php`
  `testIssueRefreshTokenRefusesASessionWithoutUsableIdentifier`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserRejectsTokenWhenPidHintResolvesToNullPrincipal`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserRejectsTokenWhenPidHintDoesNotMatchResolvedPrincipal`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserRejectsTokenWhenResolvedPrincipalIdentifierIsNull`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserRejectsTokenWhenDidHintCannotBeResolved`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserAttributesTheFailureToTheResolvedIdentityWhenDidHintCannotBeResolved`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserRejectsTokenWhenDidHintNamesRevokedSession`, `testUserRejectsTokenWhenDidHintNamesSessionThatHasEnded`
- `tests/Integration/Guards/SessionLifetimeIntegrationTest.php`
  `testBearerRejectsASessionThatHasEnded`, `testLeewayDoesNotOutliveTheAbsoluteDeadline`,
  `testAttemptCannotPinASessionThatHasEnded`
- `tests/Integration/Guards/JwtGuardIntegrationTest.php`
  `testRevokingSessionBlocksRefreshAndExistingAccessToken`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testBearerRejectsSessionRevokedOnThePrimaryWhileTheReplicaLags`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testBearerRejectsSessionWhoseRevocationIsRecordedOnThePrimaryWhileTheReplicaLags`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testBearerRejectsSessionWhoseEndIsRecordedOnThePrimaryWhileTheReplicaLags`,
  `testAttemptRejectsPinnedSessionWhoseEndIsRecordedOnThePrimaryWhileTheReplicaLags`
- `tests/Integration/Guards/UncastRevokedSessionIntegrationTest.php`
  `testBearerRejectsTheRevokedSession`, `testAttemptRejectsTheRevokedSessionWhenPinned`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserReportsDidHintNamingSessionLoadedWithoutItsRevocation`,
  `testUserBuildsTheSessionsRelationWithReadsPinnedToTheWriteConnection`
- `tests/Integration/Guards/PartiallySelectedSessionIntegrationTest.php`
- `tests/Integration/Guards/SessionRelationWriteConnectionIntegrationTest.php`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserRejectsMalformedDidHintWithoutQueryingSessions`
- `tests/Feature/Guards/JwtGuardUserResolutionTest.php`
  `testUserPropagatesDatabaseErrorFromSessionLookup`
- `tests/Feature/Guards/JwtGuardRefreshResolutionTest.php`
  `testRefreshReturnsNullWhenPrincipalIsUnresolved`
- `tests/Feature/Guards/JwtGuardRefreshResolutionTest.php`
  `testRefreshReturnsNullWhenPidHintDoesNotMatchResolvedPrincipal`
- `tests/Feature/Guards/JwtGuardRefreshResolutionTest.php`
  `testRefreshReturnsNullWhenResolvedPrincipalIdentifierIsNull`
- `tests/Integration/Guards/GuardScopedPrincipalResolverIntegrationTest.php`
  `testGuardsResolveDifferentPrincipalsWithoutCrossContamination`
- `tests/Integration/Guards/AccessOnlyIntegrationTest.php`
  `testForgedSessionHintFailsClosedWithoutSessionsTable`
- `tests/Integration/Guards/JwtGuardResolutionFreshnessIntegrationTest.php`
  `testBearerRejectsPreviouslyIssuedTokenWhenResolvedPrincipalBecomesInactiveBetweenRequests`
- `tests/Integration/Guards/JwtGuardResolutionFreshnessIntegrationTest.php`
  `testBearerRejectsPreviouslyIssuedTokenWhenHintedSessionIsDeletedBetweenRequests`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testBearerReadsIdentityAndSessionFromTheWriteConnection`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testDefaultResolverReadsPrincipalsFromTheWriteConnection`
- `tests/Integration/Guards/JwtGuardEagerLoadWriteConnectionIntegrationTest.php`
  `testBearerRejectsMemberWhoseEagerLoadedTenantIsDeactivatedOnThePrimary`
- `tests/Integration/Guards/JwtGuardEagerLoadWriteConnectionIntegrationTest.php`
  `testBearerRejectsUserWhoseEagerLoadedTenantIsDeactivatedOnThePrimary`
- `tests/Integration/Guards/JwtGuardCrossConnectionTenantIntegrationTest.php`
  `testBearerRejectsMemberWhoseLandlordTenantIsDeactivatedOnItsPrimary`
- `tests/Integration/Guards/JwtGuardCrossConnectionTenantIntegrationTest.php`
  `testBearerRejectsMemberWhoseEagerLoadedLandlordTenantIsDeactivatedOnItsPrimary`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testBearerRejectsIdentitySuspendedOnThePrimaryWhileTheReplicaLags`

## Change Triggers

Update this note when any of the following change:

- how `principal` and `sid` are matched or coerced
- which claims each token type requires (`TokenType::requiredClaims()`)
- how a `sid` is checked against the session model's key format before the lookup
- whether hinted principal resolution can short-circuit through `ResolvesHintedPrincipal`
- whether bearer `sid` remains identity-scoped through `HasSessions`
- whether a revoked or ended session is still rejected on the bearer path like a missing one
- whether refresh `sid` remains backed by the configured session model
- how late-path bearer failures are attributed on the `AuthenticationFailed` event
- whether the identity, principal, tenant, and session reads still go to the write connection
- how guard-local or rebound principal resolvers are propagated into refresh
