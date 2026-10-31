# Refresh Rotation and Replay

## Purpose

This note documents the package's refresh-token contract. Access tokens are self-verifying JWTs; refresh tokens are
signed JWTs bound to a device row, which holds the session's refresh credential, its deadlines, and its revocation
state. Every refresh rotates that credential, honours the token it replaced for a short grace window, and treats any
other rotated token as a replay that revokes the device.

## Invariants

- Refresh tokens stay signed JWTs and are bound to a device via `did`. A rotation id is only usable inside a token
  signed with the guard's key and carrying the guard's `grd`.
- The token carries a plaintext rotation id in `jti`. The device row stores only SHA-256 digests: `refresh_key` for the
  current id and `previous_refresh_key` for the id it replaced, with `refresh_rotated_at` recording when it was
  replaced. Every comparison against a stored digest is constant-time.
- A device's first rotation id is random (`RefreshTokenHasher::generate()`). Each rotation replaces the current id `R`
  with `RefreshTokenHasher::successor(R)`, an HMAC-SHA256 of a fixed label keyed by `R`. Successors are deterministic so
  that a retry of `R` can be handed the current id again without the server storing any id in plaintext; knowing a
  future id gives nothing away, because it is only usable inside a signed token, and the row's digests reveal no id.
- One time, `$now`, is taken per exchange right after the token is parsed and cut to the whole second (the precision
  every device timestamp is stored at). Every check, every value written, and both issued tokens' `iat` use it, so a
  request that later waits on a row lock is still judged at the moment it started. Application servers are expected to
  keep synchronised clocks.
- A device is a session with an idle and an absolute deadline, both required. A session has ended from the second either
  deadline names, or when either is missing (`DeviceDeadlines::hasEnded()`, the one rule shared by refresh, the bearer
  path, sign-in pins, and issuance). A rotation moves the idle deadline to `idleDeadline($now, absolute)`, the idle
  lifetime from `$now` capped at the absolute deadline, and never writes the absolute deadline, so it is kept across
  rotations. A refresh token expires at the earlier of the two deadlines, and an access token after the access lifetime
  but never after the earlier of the two deadlines, from which the bearer path rejects it, so no token outlives its
  session even when the idle lifetime is shorter than the access lifetime.
- The rotation is a single compare-and-swap `UPDATE` on the device's own connection that applies only while the row
  still holds the presented id as current, is not revoked, and has both deadlines exactly as they were loaded (equality
  on the raw stored values, exact because the columns are whole-second). It records the presented digest as previous,
  `$now` as the rotation time, the successor's digest as current, and the new idle deadline. There is never more than
  one swap per exchange.
- The new pair is issued before the swap, and returned only once the swap has committed. A failure while issuing
  (signing, randomness, an identifier that cannot be read) therefore happens before anything is written and leaves the
  presented refresh token valid.
- A grace retry writes no rotation state: no swap, and the digests, rotation time, and deadlines stay as they are. The
  grace window is anchored at the real rotation, so retries can never extend it.
- Revocation marks the row (`revoked_at`, `revoked_reason`) and clears both digests in one guarded `UPDATE` that only
  applies to a row that is not yet revoked; it never deletes the row. It is idempotent and keeps the first
  revocation's time and reason. `DeviceRevoked` is dispatched only by the call that revoked the device, and only once
  the revocation is committed on the device's own connection: at once when that connection has no open transaction,
  when its transaction commits otherwise, and never when that transaction is rolled back. A transaction open on another
  connection neither delays nor cancels it, because the revocation was not written in it.
- Refresh reads device state live on every exchange, from the write connection, so a lagging read replica cannot serve
  a stale digest, rotation time, deadline, or revocation. The device lookup, the locking re-read, and every state read
  (`getRevokedAt()`, both deadlines, `getRefreshKey()`, `getPreviousRefreshKey()`, `getRefreshRotatedAt()`) run inside
  `WriteConnection::during()`, so a device that derives any of them from a relation (eager-loaded or not) or another
  table reads it from the writer too. So do the deadline reads that cap the issued pair's `exp`, on a rotation, a grace
  retry, and direct issuance alike. A device loaded without one of these columns throws a `LogicException` instead of
  being admitted or revoked on a missing value. The owner, principal, and tenant behind the activity checks are read
  from the write connection too, including a tenant the owner or principal eager-loads and a tenant kept on another
  connection.
- Refresh applies the same opt-in activation checks as sign-in and bearer requests: the reloaded owner, the resolved
  principal, and the tenant it acts within must each be active when they implement `CanBeActive`.
- A device is a session of one guard (its `guard` column, stamped by the session service). Refresh honours a token only
  for a device of the guard exchanging it, checked right after the lookup and before anything else is judged, so a
  token of one guard can never revoke, rotate, or even classify another guard's device; the bearer path and sign-in pins
  treat such a device as missing. A device that records no guard belongs to none.
- Refresh holds every session to the guard's current audience policy (`AudiencePolicy`, resolved from the container on
  each exchange): the method that started the session (`sign_in_method`) must still be one the guard allows, and the
  policy must still admit the owner as the principal (asked without an identifier type, so the verified-identifier
  requirement never applies to a refresh). Neither failure revokes: the session refreshes again once the policy allows
  it. A rotation's idle lifetime is the one the policy gives the principal's type; the grace window and leeway stay the
  guard's, since they apply before the principal is known.
- Refresh counts failures, not attempts: it cannot guess a secret (signed tokens, 256-bit rotation ids), so each failed
  exchange is counted against the token's device and the client's IP address by the bound `AttemptLimiter`, and
  successful ones are not. Once either count is full, the exchange stops before the device lookup.
- Refresh preserves principal continuity by carrying `pid` forward into both the new refresh token and the new access
  token.
- A refresh is accepted only for the principal its device records (`PrincipalReference::isRecordedOn()`), on the
  current, the grace and the lost-rotation paths alike: after a switch of principal, the refresh token of the principal
  switched from fails with `device_principal_mismatch` and is not a replay, so the device is left alone, while the same
  token after the grace window is judged a replay as any rotated token is. The switch itself runs the same judgement
  (`RefreshJudgement::classify()`) with its own retry rule; see `principal-choice-and-switch.md`.
- The package opens no transaction around a refresh.

## Success Path

- Parse the refresh JWT (which must carry this guard's `grd`). Ask the limiter whether the token's `did` (none for a
  token that does not parse) or the client's IP address has used up its failures; if so, stop with `rate_limited`.
- Extract `did`, `jti`, and optional `pid`, and load the configured device model by primary key from the write
  connection (`DeviceLookup::find()`); take `$now`.
- Refuse a device whose `guard` is not this guard (or is `null`) with `device_guard_mismatch`.
- Classify the device at `$now`, before any identity or principal is loaded and before any rotation id is compared:
  1. revoked: `device_revoked`;
  2. session ended (either deadline reached or missing): `session_expired`;
  3. no current digest: `refresh_key_missing`;
  4. the presented id matches the current digest: CURRENT;
  5. the presented id matches the previous digest, the rotation time is set, `$now` is before the rotation time plus
     `refresh_grace_seconds`, and the successor of the presented id matches the current digest: GRACE;
  6. anything else: a replay (`rotation_reuse`).
- Reload the device's owner through the guard's identity provider, confirm it is that exact owner (see
  `guard-bound-tokens.md`) and that it is active; resolve the principal (the `pid` one when the token carries it) and
  confirm it and its tenant are active.
- Ask the audience policy: `allowsMethod(guard, sign_in_method)` (a `null` method fails without asking) and
  `admit(guard, identity, principal, null)`.
- CURRENT: compute the successor and the new idle deadline (from `AudiencePolicy::lifetimes(guard, principal)`), issue
  the access token and a refresh token carrying the successor at `$now`, then run the compare-and-swap. When it affects
  the row, mirror the new state on the in-memory device and return the pair.
- GRACE: issue, at `$now`, a fresh access token and a refresh token whose `jti` is the current id (the successor of the
  presented one) and whose `exp` is the stored idle deadline (capped at the absolute deadline), and return them. Both
  holders of the replaced token now hold the current id: the next refresh by either rotates normally, and the other
  becomes a grace retry or, after the window, a replay.
- A grace retry is a successful refresh and fires the same events as a rotation (`Attempting`, `Refreshed`, `SignedIn`,
  `Validated` and the bind events). The last-use listener may still record the use, as on any authentication.

## Failure / Edge Cases

- Every failure below is returned by `exchange()` as an `AuthenticationFailed` (flow `refresh`), undispatched, after it
  is counted against the token's device and the client's IP address; the session service's `refresh()` then dispatches
  `Failed` and the `AuthenticationFailed`, and returns a failed `RefreshResult` with the reason.
- Once the device's or the IP address's count is full, the exchange fails with `rate_limited` before the lookup,
  carrying the seconds until the full count's window ends (`retryAfter`), and that failure is not counted itself, so a
  blocked client costs one read. `refresh()` dispatches `Failed` and `AuthenticationFailed` and returns `rate_limited`
  with the same `retryAfter`, never thrown (a throttled refresh is an outcome, see `outcomes.md`); the route answers it
  with a 429 and `Retry-After`, since a 401 would be wrong.
- A device of another guard, or of none, produces `device_guard_mismatch` without a write to the device, even for a
  token that would be a replay, and nothing is hydrated.
- A device whose `sign_in_method` the guard no longer allows, or which records none, produces `method_not_allowed`; an
  owner the guard's audience policy no longer admits as the principal produces `principal_ineligible`. Neither writes
  to the device or revokes it.
- Missing or malformed claims produce `token_invalid`: a refresh token must carry `exp`, `iat`, `jti`, `typ`, `grd`, and
  `did` (`pid` is optional). The token's own `exp` is checked by `parse()` (with leeway) before `$now` is taken; the
  row's deadlines are authoritative and apply without leeway.
- Unknown device ids produce `device_unknown`, and so does a `did` that cannot be a key of the device model, which is
  rejected before the device lookup.
- Database errors are not a failure reason: they propagate to the caller as server errors on every query (lookup, swap,
  re-read, revocation), so an outage is never reported as an unknown device.
- Revoked devices produce `device_revoked` without a write. Revocation is not refresh-only: the bearer path rejects an
  access token naming a revoked device as if the device were missing (see `fail-closed-pid-did.md`).
- An ended session produces `session_expired` without a write. Ending is not revocation: the row is left for pruning,
  and the bearer path rejects the device's access tokens too.
- A device with no current digest produces `refresh_key_missing` without a write: it holds no refresh credential, so a
  token for it cannot be classified as a replay, and the device is not revoked.
- A replay (an older id, the previous id after the window or with a grace window of 0, the previous id when the current
  digest is not its successor, or any id the device never held) revokes the device with reason `rotation_reuse` and
  dispatches `DeviceRevoked`, the refresh's `Failed`, and `AuthenticationFailed` (`rotation_reuse`). With no transaction
  open on the device's connection they come in that order; inside one, `Failed` and `AuthenticationFailed` come first
  and `DeviceRevoked` follows the commit (the transaction Laravel's testing traits wrap around each test is not counted,
  as it never commits). Nothing is hydrated. Every token of the device then fails: access tokens on the bearer path,
  refresh tokens with `device_revoked`.
- "Any id the device never held" includes a validly signed token from an earlier credential of the same row. A device
  is given a refresh credential outside a rotation only by the session service: when it creates the device, and when a
  client that proved it holds the device with its current refresh token signs in again on it. Continuing a device sets
  a new current id and clears `previous_refresh_key` and `refresh_rotated_at` in one compare-and-swap that applies only
  while the row still holds the proven digest, is not revoked, and records the same owner and principal, so every
  earlier token of the device becomes a replay: presenting one while the new session is live revokes the device (RFC
  9700). That is deliberate. The client that proved the device has just received the new pair, and one that lost the
  sign-in response and retries with the old token proves nothing (the old id is no longer current) and gets a new
  device. A swap that misses (a parallel refresh rotated the device first) never retries: the sign-in is reconsidered
  without the device, so it starts on a new device, or becomes a pending sign-in when the additional-factor policy now
  asks for a factor.
- Only the immediately previous id is honoured: after `R0 -> R1 -> R2`, a delayed retry of `R0` is a replay even within
  the grace window of the first rotation, and revokes the device.
- When the swap affects no row, the row changed between the read and the write. The exchange re-reads it once from the
  writer with a locking read (`lockForUpdate()`, a no-op on SQLite) and classifies it again at the same `$now`:
  - GRACE, the usual case (a parallel refresh with the same token rotated first, and its successor is this exchange's):
    the exchange returns the current credential as above, after confirming the fresh row still belongs to the hydrated
    identity (`identity_unknown` otherwise);
  - a replay (for example with a grace window of 0): the device is revoked, `rotation_reuse`;
  - revoked, deleted, ended, or credential cleared meanwhile: `device_revoked`, `device_unknown`, `session_expired`, or
    `refresh_key_missing`;
  - the presented id is still current, so other security state changed (a deadline moved): `rotation_conflict`, with
    no revocation and no second swap. That proves nothing about theft, so the device is not revoked, and a client retry
    is judged against the new state.
- One reason or two: two. Proven reuse has one revoking reason, `rotation_reuse`. The swap race is no longer a reuse
  signal; it resolves by reclassification, and the residual conflict that proves nothing gets the non-revoking
  `rotation_conflict`, because revoking for it would sign people out without cause.
- A revocation committed while a grace retry is in flight can still let that retry return a pair, but every token of a
  revoked device is rejected on its next use, so nothing outlives the revocation.
- Transactions: in autocommit or READ COMMITTED, a parallel refresh inside the window resolves to GRACE. Inside a
  caller's REPEATABLE READ transaction, MySQL's locking re-read sees the latest committed row and the outcome is the
  same; PostgreSQL raises a serialization failure (SQLSTATE 40001) on the swap or the re-read, which propagates as a
  server error for the caller to retry, with nothing revoked. A caller that rolls back a transaction on the device's
  connection around `refresh()` also rolls back a replay revocation, and `DeviceRevoked` is then never dispatched; do
  not roll back around refresh.
- An exception while issuing the new pair propagates without an `AuthenticationFailed` event and without touching the
  device row, so the client can retry with the same refresh token.
- After the swap, `refresh()` schedules `Refreshed` and `SignedIn` for the rotation's commit on the device's connection
  before it binds the new context (`Validated`, `Login` and the bind events), so a listener that throws on a bind event
  cannot withhold `Refreshed`. With no transaction open there they are dispatched at once, before the bind events;
  inside a caller's transaction the bind events come first, and they follow the commit or are dropped on a rollback.
  Such an exception (on `Validated`, `Login`, `Authenticated`, `PrincipalAssigned`, `DeviceAuthenticated`, including the
  package's own last-use write, or on `Refreshed` or `SignedIn`) still propagates after the presented token has been
  rotated and the new pair is lost. A retry with the presented token inside the grace window gets the current
  credential; after the window it is a replay and revokes the device. Listeners on these events should not throw, or
  should be queued.
- An inactive owner, principal, or tenant produces `identity_inactive`, `principal_inactive`, or `tenant_inactive`. A
  principal whose tenant key names a tenant that implements `CanBeActive` but cannot be loaded (deleted or
  soft-deleted) also produces `tenant_inactive`.
- An `UnresolvableIdentityException` from the principal resolver is a misconfiguration, not a failure reason: it
  propagates as a server error without an `AuthenticationFailed` event, and the stored digests are left as they were.
- Device times are stored as wall-clock times in the application timezone without an offset, as Laravel stores
  `datetime` columns, so the package expects `app.timezone` to be UTC (Laravel's default) or another zone without
  daylight saving. In a zone with daylight saving, both passes through the hour that repeats when the clocks go back
  store the same value. PHP reads that value as the first pass in some zones (New York) and as the second in others
  (London, Berlin, Sydney), and the second would make a first-pass deadline or rotation read late: a session would
  outlive its deadline, and a replay of the previous token up to an hour after a rotation would be a grace retry.
  `ActsAsDevice` therefore reads every device time as the earliest instant its wall-clock time could be
  (`ReadsDeviceAttributes::earliestInstantOf()`), so the ambiguity only ever moves a time earlier: a deadline stored in
  the second pass ends the session early by the length of the shift (when the idle lifetime is no longer than the shift,
  the refresh that sets it reads it back as already reached, so issuing the new pair throws `InvalidArgumentException`
  before anything is written), and a rotation stored there leaves no grace window (at most 300 seconds, less than any
  shift), so a retry of the previous token is a replay and revokes the device. Storing UTC whatever the application
  timezone would remove the ambiguity, but the application's own queries against these columns (Laravel binds a date in
  its own timezone) and any custom device model that keeps Laravel's `datetime` cast would then disagree with the stored
  values whenever the timezone's offset is not zero.
- Refresh does not rely on Eloquent observers. The swap and the revocation are query-builder updates that deliberately
  bypass them; consumers should hang side effects off `AuthenticationFailed`, `Refreshed`, and `DeviceRevoked` instead.

## Implementation Anchors

- `src/Jwt/RefreshTokenExchange.php`: `exchange()` (the limiter check and the failure count), `exchangeClaims()`,
  `exchangeOn()` (the guard check), `extractRefreshClaims()`, `hydrateRefreshContext()` (the recorded principal),
  `rotate()`, `afterLostRotation()`, `reissue()`, `fail()`, `revokeDevice()`.
- `src/Jwt/RefreshJudgement.php`: `classify()` and `isGraceRetry()`, the verdict a refresh and a switch of principal
  share.
- `src/Jwt/RefreshAdmission.php`: `admit()` (the owner reload, the principal, activity), `admitByPolicy()` (the
  audience policy).
- `src/Jwt/RefreshRotationStore.php`: `rotate()` (the compare-and-swap), `switchPrincipal()` (the switch's
  compare-and-swap), `revoke()` (the guarded revocation), and `reload()` (the locking re-read on the writer).
- `src/Database/AfterCommit.php`: defers `DeviceRevoked` to the commit of the device's own connection.
- `src/Devices/DeviceLookup.php`: `find()`, the device lookup on the writer.
- `src/Contracts/AudiencePolicy.php` and `src/Contracts/AttemptLimiter.php`: the policy and the limiter each exchange
  resolves from the container.
- `src/Jwt/RefreshTokenHasher.php`: `generate()`, `successor()`, `hash()`, and constant-time `verify()`.
- `src/Devices/DeviceDeadlines.php`: `hasEnded()` and `liveDeadlines()`.
- `src/Jwt/TokenLifetimes.php`: `idleDeadline()`, `accessExpiry()`, and `isWithinGrace()`; the factory resolves
  `refresh_grace_seconds` with the lifetimes in `src/Jwt/JwtTokenServiceFactory.php`.
- `src/Jwt/JwtTokenService.php`: `issueRefreshToken()` and `issueAccessToken()`, each with `$issuedAt`.
- `src/Jwt/Enums/RotationMatch.php`: the CURRENT and PREVIOUS verdicts.
- `src/Devices/DeviceKeyShape.php` and `src/Contracts/ValidatesDeviceKey.php`: the `did` shape check run before the
  device lookup.
- `src/Database/WriteConnection.php`: pins the device and owner reads to the write connection (the principal and tenant
  reads are pinned by the resolver and by `ActivationPolicy`).
- `src/Admission/ActivationPolicy.php`: the opt-in identity, principal, and tenant activity checks.
- `src/Events/Enums/FailureReason.php` and `src/Events/Enums/RevocationReason.php`: failure and revocation
  taxonomies; `src/Events/AuthenticationFailed.php`, `src/Events/DeviceRevoked.php`.
- `src/Sessions/SessionRefresh.php`: `refresh()` runs the live refresh exchange with the request's client, `report()`
  schedules `Refreshed` and `SignedIn`, the binding's `loginVerified()` binds, and `refuse()` reports a refusal and
  returns it with its reason and wait; `src/Sessions/SessionService.php` builds the exchange on the guard's context and
  token service. `src/Sessions/RefreshResult.php`: the outcome.
- `src/Devices/OwnedDevice.php`: `refusal()`, which refuses a device of another guard on the bearer path
  (`device_guard_mismatch`) and for sign-in pins (`resolveDeviceFromHint()` in
  `src/Guards/Concerns/VerifiesPinnedContext.php`).
- `src/Concerns/ReadsDeviceAttributes.php`: `toDeviceTimestamp()` and `earliestInstantOf()`, which read a device time
  in the repeated daylight saving hour as its first pass.

## Authoritative Tests

- `tests/Feature/Jwt/RefreshJudgementTest.php` (every verdict, and the order the session's state is judged in)
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testARefreshAsAPrincipalTheDeviceNoLongerRecordsIsRefused`, `testLostRotationFailsWithWhatTheRowNowSays`
- `tests/Feature/Sessions/PrincipalSwitchTest.php`
  `testTheOldRefreshTokenInsideTheGraceWindowFailsWithoutRevoking`,
  `testTheOldRefreshTokenAfterTheGraceWindowRevokesTheDevice`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testExchangeRotatesTheCurrentRotationIdToItsSuccessor`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testGraceRetryGetsTheCurrentCredentialWithoutWriting`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testReplayRevokesTheDevice`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testOnlyTheImmediatelyPreviousRotationIdIsHonoured`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testDeviceWithoutARefreshCredentialIsRejectedWithoutRevoking`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testDeviceLoadedWithoutItsPreviousDigestIsReportedNotRevoked`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testRevokingADeviceIsIdempotent`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testLostRotationToAParallelRefreshIsAGraceRetry`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testLostRotationIsJudgedAtTheExchangesOwnTime`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testLostRotationWithGraceDisabledRevokesTheDevice`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testLostRotationFailsWithWhatTheRowNowSays`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testExchangeRejectsAnEndedSessionWithoutWriting`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testExchangeLeavesTheRefreshTokenValidWhenIssuingFails`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testExchangeUsesPidHintWhenRefreshTokenCarriesPrincipalId`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testExchangeRejectsMalformedDeviceIdWithoutQuerying`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testExchangePropagatesUnresolvableIdentityException`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testABlockedExchangeIsRefusedBeforeTheLookup`, `testEveryFailureIsCountedAgainstTheDeviceAndTheIpAddress`,
  `testASuccessfulExchangeIsNotCounted`, `testADeviceOfAnotherGuardIsRefusedWithoutRevokingIt`,
  `testTheMethodThatStartedTheSessionMustStillBeAllowed`, `testThePolicyMustStillAdmitTheOwnerAsThePrincipal`,
  `testARotationMovesTheIdleDeadlineByThePrincipalsLifetimes`
- `tests/Feature/Guards/JwtGuardTest.php`
  `testARateLimitedRefreshFiresFailedAndReturnsTheWait`
- `tests/Feature/Sessions/SessionRefreshTest.php`
  `testEveryRefusalIsReturnedWithItsReason`, `testARateLimitedRefreshIsReturnedWithItsWait`,
  `testTheRotationIsReportedBeforeTheBind`, `testTheReportWaitsForTheCallersCommit`
- `tests/Integration/Http/RefreshCookieSessionLifecycleTest.php`
  `testARateLimitedRefreshIsAnsweredWithRetryAfter`
- `tests/Feature/Guards/VerifiesPinnedContextTest.php`
  `testPinnedDeviceOfAnotherGuardFailsTheAttempt`
- `tests/Integration/Guards/RefreshAudienceIntegrationTest.php`
  `testADeviceOfAnotherGuardIsNeitherRefreshedNorRevoked`, `testASessionOfAMethodNoLongerAllowedIsNotRefreshed`,
  `testADeviceThatRecordsNoMethodIsNotRefreshed`, `testAnOwnerTheAudienceNoLongerAdmitsIsNotRefreshed`,
  `testARotationFollowsThePrincipalsIdleLifetime`, `testAFailedRefreshIsCountedAgainstTheDeviceAndTheIpAddress`,
  `testARateLimitedRefreshIsAnswered429WithRetryAfter`
- `tests/Feature/Jwt/RefreshRotationStoreTest.php`
  `testRotateRecordsTheRotationAndMirrorsIt`, `testRotateMissesAfterAChangeSinceTheDeviceWasLoaded`,
  `testRevokeKeepsAnEarlierRevocation`, `testReloadReadsTheRowAsItNowIs`, `testWritesTouchOnlyTheDevicesOwnRow`,
  `testWritesAndReadsUseTheDevicesOwnConnection`
- `tests/Feature/Database/AfterCommitTest.php`
  `testWaitsForTheDeviceConnectionsTransaction`, `testDropsWorkRolledBackWithANestedTransaction`,
  `testIgnoresTheTransactionWrappingATest`, `testIgnoresTransactionsOnOtherConnections`
- `tests/Feature/Guards/JwtGuardRefreshTest.php`
  `testRefreshRevokesTheDeviceForARotationIdItDoesNotHold`
- `tests/Feature/Guards/JwtGuardRefreshTest.php`
  `testRefreshRevokesTheDeviceWhenItsDigestIsReplacedBeforeTheSwap`
- `tests/Feature/Guards/JwtGuardRefreshTest.php`
  `testReplacedRefreshTokenIsHonouredInsideTheGraceWindowOnly`
- `tests/Feature/Guards/JwtGuardRefreshTest.php`
  `testRefreshReturnsNullWhenDeviceHasBeenRevoked`
- `tests/Feature/Guards/JwtGuardRefreshResolutionTest.php`
  `testRefreshRotatesAndIssuesNewTokenPairOnSuccess`
- `tests/Integration/Guards/RefreshReplayIntegrationTest.php`
  `testParallelRefreshesWithOneTokenBothGetTheCurrentCredential`
- `tests/Integration/Guards/RefreshReplayIntegrationTest.php`
  `testParallelRefreshesWithGraceDisabledRevokeTheDevice`
- `tests/Integration/Guards/RefreshReplayIntegrationTest.php`
  `testReplayRevokesTheDeviceAndEndsItsAccessTokens`
- `tests/Integration/Guards/RefreshReplayIntegrationTest.php`
  `testLostResponseIsRecoverableInsideTheGraceWindowOnly`
- `tests/Integration/Guards/RefreshReplayIntegrationTest.php`
  `testRevocationIsReportedOnlyAfterCommit`
- `tests/Integration/Guards/RefreshReplayIntegrationTest.php`
  `testParallelRefreshInsideARepeatableReadTransaction`
- `tests/Integration/Guards/RefreshReplayIntegrationTest.php`
  `testRotationAndReplayTouchOnlyTheirOwnDevice`
- `tests/Integration/Guards/SeparateDeviceConnectionIntegrationTest.php`
  `testRefreshAndBearerUseTheDevicesOwnConnection`,
  `testReplayIsReportedAtOnceWhateverAnotherConnectionsTransactionDoes`,
  `testReplayInsideTheDeviceConnectionsTransactionIsReportedOnItsCommit`,
  `testReplayRolledBackWithANestedTransactionIsNeverReported`
- `tests/Integration/Guards/ReplayUnderDatabaseTransactionsIntegrationTest.php`
  `testReplayOutsideTheApplicationsTransactionsIsReportedAtOnce`,
  `testReplayInsideTheApplicationsTransactionIsReportedWhenItCommits`
- `tests/Integration/Guards/SessionLifetimeIntegrationTest.php`
  `testRefreshMovesTheIdleDeadlineAndKeepsTheAbsoluteDeadline`
- `tests/Integration/Guards/SessionLifetimeIntegrationTest.php`
  `testRefreshNeverExtendsTheSessionPastItsAbsoluteDeadline`
- `tests/Integration/Guards/SessionLifetimeIntegrationTest.php`
  `testRefreshFailsFromTheSecondEitherDeadlineIsReached`
- `tests/Integration/Guards/SessionLifetimeIntegrationTest.php`
  `testRotationConflictsWhenADeadlineMovesBeforeItCommits`
- `tests/Integration/Guards/UncastRevokedDeviceIntegrationTest.php`
  `testRefreshRejectsTheRevokedDeviceWithDeviceRevokedReason`
- `tests/Integration/Guards/JwtGuardRefreshPrincipalContinuityIntegrationTest.php`
  `testRefreshPreservesOriginalPrincipalTenantAndTypeWhenDefaultDiffers`
- `tests/Integration/Guards/JwtGuardIntegrationTest.php`
  `testRevokingDeviceBlocksRefreshAndExistingAccessToken`
- `tests/Integration/Guards/JwtGuardResolutionFreshnessIntegrationTest.php`
  `testRefreshRejectsTokenWhenIdentityBecomesInactiveAfterIssuance`
- `tests/Integration/Guards/JwtGuardResolutionFreshnessIntegrationTest.php`
  `testRefreshRejectsTokenWhenDeviceIsDeletedAfterIssuance`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testRefreshReadsDeviceAndIdentityFromTheWriteConnection`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testRefreshRejectsDeviceWhoseRevocationIsRecordedOnThePrimaryWhileTheReplicaLags`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testRefreshRejectsDeviceWhoseSessionEndIsRecordedOnThePrimaryWhileTheReplicaLags`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testRotationCapsTheIssuedPairAtTheSessionEndRecordedOnThePrimary`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testGraceRetryCapsTheIssuedPairAtTheSessionEndRecordedOnThePrimary`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testGraceRetryIsJudgedFromThePrimaryWhileTheReplicaLags`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testReplayIsJudgedFromThePrimaryWhileTheReplicaLags`
- `tests/Integration/Guards/JwtGuardWriteConnectionIntegrationTest.php`
  `testLostRotationIsJudgedFromThePrimaryWhileTheReplicaLags`
- `tests/Integration/Guards/JwtGuardDatabaseFailureIntegrationTest.php`
  `testRefreshPropagatesAConnectionFailureDuringDeviceLookup`
- `tests/Integration/Guards/TenantActivityIntegrationTest.php`
  `testRefreshRejectsMemberOfInactiveTenantWithTenantInactiveReason`
- `tests/Integration/Guards/TenantActivityIntegrationTest.php`
  `testRefreshRejectsMemberOfSoftDeletedTenantWithTenantInactiveReason`
- `tests/Unit/Jwt/RefreshTokenHasherTest.php`
  `testSuccessorIsADeterministicRotationIdOfTheSameShape`, `testSuccessorIsTheLabelledHmacOfTheRotationId`,
  `testSuccessorChainsDoNotRepeat`
- `tests/Unit/Jwt/TokenLifetimesTest.php`
  `testGraceWindowEndsAtItsLastSecond`, `testZeroGraceWindowNeverApplies`
- `tests/Unit/Traits/ActsAsDeviceTest.php`
  `testTimestampGetterReadsARepeatedHourTimeAsItsEarlierInstant`
- `tests/Integration/Guards/RepeatedHourStorageIntegrationTest.php`
  `testTimesInTheRepeatedHourReadBackAsTheFirstPass`,
  `testWithDaylightSavingAReplayAfterARotationInTheFirstPassIsNotAGraceRetry`,
  `testWithUtcARotationAtTheEndOfTheRepeatedHourKeepsItsGraceWindow`,
  `testWithDaylightSavingARotationInTheSecondPassLeavesNoGraceWindow`,
  `testWithDaylightSavingARefreshSettingAnIdleDeadlineInTheSecondPassFailsWithoutWriting`,
  `testWithDaylightSavingADeadlineInTheSecondPassEndsTheSessionEarly`
- `tests/Integration/Sessions/SignInPolicyEndToEndTest.php` (the shipped policy and limiter)
  `testTheGuardAdmitsOnlyTheListedPrincipalTypesOnSignInAndRefresh`,
  `testRefreshesRefusedForTheirFailuresAreAnswered429ThroughTheRoute`
- `tests/Performance/RefreshTokenExchangeQueryBudgetTest.php` (every refresh reads its limits once; a failure counts
  itself)
  `testRefreshSuccessUsesThreeReadsAndOneWrite`, `testGraceRetryUsesThreeReadsAndNoWrites`,
  `testLostRotationResolvedAsAGraceRetryUsesFourReadsAndOneWrite`,
  `testReplayRevocationReadsTheDeviceAndRevokesItInOneWrite`, `testMissingRefreshCredentialStopsAtTheDeviceLookup`,
  `testEndedSessionRefreshFailureStopsAtTheDeviceLookup`, `testMalformedDeviceIdRefreshFailureSkipsTheDeviceLookup`,
  `testGraceAndReplayCostNoMoreThanARotation`

## Change Triggers

Update this note when any of the following change:

- the digest algorithm, the decision to store digests rather than plaintext rotation ids, or how `successor()` derives
  the next rotation id
- the compare-and-swap predicate or the columns a rotation writes
- whether the new pair is still issued before the swap commits
- the grace window: its anchor, its default, what a retry receives, or whether more than the immediately previous id is
  honoured
- how a lost swap is resolved, or whether an exchange can ever run a second swap
- the meanings of `rotation_reuse`, `rotation_conflict`, `refresh_key_missing`, `session_expired`, `device_revoked`, or
  `device_unknown`, or which of them revokes the device
- whether replay revokes one device row or a broader credential family, or whether revocation marks or deletes the row
- whether code other than the session service (device creation and continuing a proven device) can give a device a new
  refresh credential, or what proves a device
- when `DeviceRevoked` is dispatched
- whether a rotation can move the absolute deadline, or how the idle deadline and token expiries are derived
- whether database errors still propagate instead of mapping to a failure reason
- whether refresh still preserves `pid` across the new pair
- whether refresh ever starts consulting shared cross-request caches
- whether refresh still reads the device and its owner from the write connection
- how device times are stored or read (wall-clock times in the application timezone, to the whole second, with the
  repeated daylight saving hour read as its first pass)
- which activity checks refresh applies, or whether an `UnresolvableIdentityException` still propagates
- whether refresh and the bearer path still bind a device to its guard, or what a device without a guard means
- which audience policy checks refresh applies (method, admission, per-type lifetimes), or whether any of them revokes
- what refresh counts against its limits, when it consults them, or how a rate-limited refresh is answered
- whether the package opens its own transaction around a refresh
