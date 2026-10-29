# Principal Choice and Switch

## Purpose

This note records how a session comes to act as one principal of an identity that may act as several: a sign-in that
names none waits for the identity to choose (`choice()`, `choose()`), and a live session moves to another principal on
the same device (`switchPrincipal()`). Starting a session is in `session-service.md`; the refresh judgement both paths
share is in `refresh-rotation-and-replay.md`; the bearer checks that end the old principal's tokens are in
`fail-closed-pid-did.md`.

## Invariants

- A choice is offered only by `signIn()` and `start()`, only when no principal is named, the resolver has no default
  (`principal_unresolved` with an identity), and the identity has at least one eligible principal; otherwise the
  sign-in fails as `principal_unresolved`, as before. `attempt()` never offers one.
- Eligible principals (`SessionService::principals()`) are the identity's `principals()` read on the write connection
  (the resolver's default for an identity that is its own principal or has no `principals()`), active, in an active
  tenant or none, and admitted by the audience policy with no identifier type. Offering a choice, and every later
  `choice()` lookup, which recomputes the list, also admits the identity (`admitIdentifier()`) and each of them with the
  sign-in's identifier type (the one the choice stores): a principal the policy then refuses is neither offered nor
  listed, and when it refuses every one the sign-in fails with that reason, storing and reporting nothing.
  `principals($identity, $identifierType)` lists the same way for a switch screen given the type the session's device
  records, so it lists only targets the audience policy lets that session switch to.
- Each principal read with the others is checked on a stored copy (`WriteConnection::stored()`): Eloquent strict mode
  prevents lazy loading on models read together, and the activity check and the audience policy read its tenant. The
  list holds the principals as read.
- Every sign-in asks the audience policy's `admitIdentifier()` before any principal is resolved or listed
  (`SignInAdmission`), so with the package's policy a guard requiring a verified identifier refuses an unverified one
  as `identifier_unverified` whether the identity has principals or not, and the answer never tells someone holding an
  unverified identity's password whether it has been invited anywhere. A policy that wraps the package's keeps this by
  asking the wrapped `admitIdentifier()`. A policy that refuses only some principals in `admit()` is asked only once a
  principal resolves, so for an identity with none the sign-in answers `principal_unresolved`.
- A choice is a pending sign-in with `purpose = principal_choice` and no principal (the pending table's principal
  columns are nullable for this). It keeps the client, the identifier type, the attempt windows, and a device the
  client proved for the identity whatever principal it records. Only the digest of its secret is stored.
- Choice and factor tokens are not interchangeable: `PendingSignIns::live()` takes the purpose, so `pending()` and
  `complete()` find only factors and `choice()` and `choose()` only choices; `discard()` takes either and reports
  `principal_choice_abandoned` or `additional_factor_failed` by purpose.
- `choose()` deletes the choice first, with a delete only one call can make, so a choice is single use whatever the
  outcome. It then runs the sign-in admission with `PinnedPrincipal::resolve()` (`principal_mismatch`), the identifier
  type the sign-in used, and the factor policy; a required factor becomes an `additional_factor` pending sign-in with
  the same windows. The proven device is continued only when it records the chosen principal and is unchanged.
- The attempt slots a sign-in took stay counted while it waits for a choice and are given back only once a session
  started from it commits.
- A switch is proven by the session's refresh token, never an access token, and judged by `RefreshJudgement::classify()`
  as a refresh is: the refresh limits (counted against the token's device and the client's IP address), the guard, a
  live session, and the rotation id. A replayed id revokes the device as `rotation_reuse`.
- Every path of a switch, the retry included, runs every live check: the owner reloaded through the guard's provider
  and active (`RefreshAdmission`), the target resolved through the hinted path, of the target's class and owned by the
  owner as read from the principal's own key (`principal_mismatch`), active, its tenant active, admitted by the
  audience policy, the session's method allowed, the identity and then the target admitted again with the type of
  identifier the session's sign-in used (the device's `sign_in_identifier_type`, written with `sign_in_method` at every
  sign-in; a session whose sign-in used none is not held to one, and a device loaded without the column throws a
  `LogicException` rather than reading as one that used none) so a principal a policy refuses to that identifier cannot
  be reached by switching, and no further factor asked (`additional_factor_required`).
- With the current rotation id, the token's `pid` must be the principal the device records
  (`device_principal_mismatch`). The absolute deadline stays the session's, held to `signed_in_at` plus the target
  type's absolute lifetime (`session_expired` when that has passed); the idle deadline restarts under the target's
  lifetimes. Both tokens are issued for the target before the write, and end at the restarted idle deadline.
- The switch is one compare-and-swap (`RefreshRotationStore::switchPrincipal()`) on the presented digest, an unrevoked
  row, both loaded deadlines and the loaded principal columns. It writes the rotation, both deadlines and, when the
  principal changes, the target and `principal_switched_at`. A switch to the recorded principal writes no switch.
- With the previous rotation id inside the grace window, the current credential is reissued for the target, writing
  nothing, only when the device records the target and either its last rotation was a switch
  (`principal_switched_at = refresh_rotated_at`) or the token's own `pid` is the target; anything else is
  `rotation_conflict`, without revoking.
- A missed swap re-reads the row with a lock and judges it once: a still-current id is `rotation_conflict`, a previous
  id is answered by the retry rule against the row as it now is (after the owner is checked again), and anything else
  fails for its reason, a replay (`rotation_reuse`) revoking the device as a first judgement does. There is never a
  second swap.
- `PrincipalChoiceRequired` and `PrincipalSwitched` are dispatched through `AfterCommit` on the device model's
  connection. `PrincipalSwitched` carries the device's recorded previous type and identifier and the previous
  principal only when the hinted path still returns that very principal (same type and identifier).

## Success Path

1. `signIn()` verifies the identity, finds no principal, and offers the choice: the pending row is written,
   `PrincipalChoiceRequired` follows the commit, and the result `requiresPrincipal()`.
2. `choice($token)` lists the eligible principals; `choose($token, $principal)` starts the session as it (`Login`,
   `DeviceCreated`, `SignedIn`), and the slots are given back after the commit.
3. Later, `switchPrincipalFromRequest($other)` (or `switchPrincipal($refreshToken, $other)` with a token read by the
   caller) rotates the device to the other principal, binds the guard to it
   (`Authenticated`, `PrincipalAssigned`, `DeviceAuthenticated`), and dispatches `PrincipalSwitched` after the commit.
   The previous principal's access tokens fail on the bearer path as `device_principal_mismatch` from then on.

## Failure / Edge Cases

- A lost switch response: the client retries with the old token inside the grace window and receives the current
  credential for the target, with no second `PrincipalSwitched`. Presented to `refresh()`, the same token fails as
  `device_principal_mismatch` without revoking.
- A switch racing a refresh of the same token loses the swap and fails as `rotation_conflict`; two identical switches
  both answer with the target's credential; two switches to different principals leave the first; a switch racing a
  revocation fails as `device_revoked`.
- A previous principal that no longer resolves (deleted, or recorded under a type the morph map no longer uses) is
  reported by its snapshot only.
- A choice whose identity no longer resolves through the guard's provider is no choice (`choice()` returns `null`,
  `choose()` fails as `pending_invalid`).
- The comparison of the expiry against `$now` reads the absolute deadline; the idle deadline is never later, so the
  two readings agree.

## Implementation Anchors

- `src/Sessions/Concerns/ChoosesPrincipals.php`: `principals()`, `choice()`, `choose()`, `switchPrincipal()`,
  `switchPrincipalFromRequest()`, `offerChoice()`, `switched()`, `previousPrincipal()`.
- `src/Sessions/PrincipalSwitch.php`: one switch, built per call; `switch()` (the limiter), `switchOn()`, `admit()`,
  `isTarget()`, `switchCurrent()`, `rotateTo()`, `retry()`, `afterLostSwitch()`, `deadlines()`.
- `src/Jwt/RefreshRotationStore.php`: `switchPrincipal()` and `reload()`.
- `src/Jwt/RefreshJudgement.php`: `classify()`, shared with the refresh exchange.
- `src/Sessions/PendingSignIns.php`: `issueChoice()`, `live()` (by purpose), `delete()`, `provenDevice()`.
- `src/Sessions/DeviceProof.php`: `provenDeviceOf()`, which proves a device without a principal for a choice.
- `src/Sessions/SessionService.php`: `signInWith()`, `startFor()` and `discard()`, which route a sign-in to a choice
  and a discard to its reason.
- `src/Events/PrincipalChoiceRequired.php`, `src/Events/PrincipalSwitched.php`, `src/Sessions/PrincipalChoice.php`,
  `src/Sessions/SwitchResult.php`.

## Authoritative Tests

- `tests/Feature/Sessions/ChoosesPrincipalsTest.php` (the choice over HTTP and through the service, choose then factor
  then complete, discard, the token purposes, the proven device, the slots, no choice for an unverified identifier,
  the listing with an identifier type, and a choice under Eloquent strict mode)
- `tests/Feature/Sessions/PrincipalSwitchTest.php` (the switch over HTTP, the old access token refused at once,
  A -> B -> A, the old refresh token inside and after the grace window, the lost response retried, every refusal, a
  switch read from the request and the transport's refusals, and a switch screen's listing)
- `tests/Integration/Sessions/PrincipalSwitchTest.php` (the switch racing a refresh, a revocation, an identical switch,
  a different switch, a deadline change, a deletion and an owner change, and a swap lost to a refresh with no grace
  window or to two refreshes, which revokes the device)
- `tests/Integration/Sessions/ConcurrentSwitchAndRevocationTest.php` (on PostgreSQL and MySQL, two processes: a switch
  waiting on a revocation, on a refresh of its token and on an identical switch, after a commit and after a rollback)
- `tests/Integration/Sessions/TransactionalChoosesPrincipalsTest.php` (`PrincipalSwitched` and
  `PrincipalChoiceRequired` only on commit, and a rolled-back choice's slots kept),
  `tests/Integration/Sessions/PrincipalChoiceEndToEndTest.php` (offer, choose, then a bearer request as the chosen
  principal)
- `tests/Integration/Sessions/ReplicaChoosesPrincipalsTest.php` (the eligible principals read on the write connection)
- `tests/Feature/Sessions/PendingSignInsTest.php` `testIssueChoiceStoresTheSignInWithoutAPrincipal`,
  `testALivePendingSignInIsFoundOnlyForItsPurpose`, `testAChoicesProvenDeviceCountsOnlyForThePrincipalItRecords`
- `tests/Feature/Jwt/RefreshRotationStoreTest.php` `testSwitchPrincipalRecordsTheTargetAndMirrorsIt`,
  `testSwitchPrincipalMissesAfterAChangeSinceTheDeviceWasLoaded`
- `tests/Integration/Http/RefreshCookieSessionLifecycleTest.php` (a switch proven by the refresh cookie, its
  cross-site checks, and the rotated cookie)
- `tests/Performance/PrincipalSwitchQueryBudgetTest.php` (seven reads and one write per switch, from the request
  too; six reads and no write per grace retry; the counters' writes alone for a refusal, and their read alone when
  rate-limited; four reads and the counters' writes and the insert per choice offered; five reads per choice read, and
  five reads and five writes per choice made; and a time ceiling for switches, retries and refusals)

## Change Triggers

Update this note when any of the following change:

- when a choice is offered, which principals are eligible, or what a choice stores
- the checks a switch runs, the order it runs them in, or the retry rule for the previous rotation id
- the switch's compare-and-swap predicate or the columns it writes
- how the deadlines of a switched session are derived
- what `PrincipalChoiceRequired` or `PrincipalSwitched` carry, or when they are dispatched
