# Session Service

## Purpose

This note records how a JWT guard's session service (`Auth::sessions($guard)`) turns a sign-in into a session: the
checks it runs and their order, how it creates a device or continues one a client proves it holds, and what it
dispatches when. It is the one place a session starts, so every sign-in method, and every external verifier that calls
`start()`, ends in the same checks.

## Invariants

- Failures are results (`SignInResult::failed()` with a `SignInFailureReason`), each reported with Laravel's `Failed` and
  then `SignInFailed`. Exceptions are reserved for misconfiguration (an unknown method, an identity that is not an
  Eloquent model, an invalid device model, an `UnresolvableIdentityException`) and server errors.
- No event ever receives the sign-in input. `Attempting` and `Failed` carry only `[type => identifier]` (or
  `['identifier' => ...]` for a method without a type, or nothing); `SignInFailed` carries the identifier as given.
- `signIn()` order: the method is resolved (unknown throws); `Attempting`; the audience policy must allow the method
  (`method_not_allowed`, nothing counted, no timebox); the attempt limiter must grant a slot (`rate_limited`); then, in
  the guard's credential timebox, cut short only for an admitted sign-in: the method verifies the input, the identity,
  the principal (the context's pin, verified like an `attempt()` pin, else the resolver's default) and its tenant must
  be active, and the audience policy must admit them with the method's identifier type; a password is rehashed; the
  proof of a device is checked; the additional-factor policy is asked; the session is written, or a pending sign-in is
  issued. Only a success gives the slots back; a pending sign-in keeps them, with their windows, until `complete()`
  starts its session. The slots are taken and given back outside the session's transaction, so a sign-in rolled back by
  its caller still counts.
- `start()` reloads the identity through the guard's provider and requires the same class and key (`identity_unknown`),
  then runs the method check, the admission with no identifier type, the device proof, the factor policy and the write.
  It takes no slot and runs in no timebox: nothing is guessed. The principal is given as the argument or on the
  context, never both.
- One `$now` per call, cut to the second, is used for the deadlines, the last use and every token's `iat`. The
  deadlines come from the audience policy's lifetimes for the principal (`AudiencePolicy::lifetimes()`), which with the
  shipped policy are the guard's `jwt.by_principal_type` entry for the principal's type, or the guard's own; the access
  token is issued with the principal's type in `pty` (see `audience-policy.md`).
- A session is written in one transaction on the device's connection: the device first, then both tokens, so any
  failure while issuing rolls the device back. Only the digest of the rotation id is stored.
- A refresh token proves a device only when it is the device's current rotation id, validly signed for the guard
  (`parseRefreshProof()`: every `parse()` check except expiry), and the device, read from the writer, is owned by the
  identity, records this guard and the same principal, and is not revoked. Anything else is no proof: a new device,
  nothing failed, revoked or reported.
- Continuing a proven device is one compare-and-swap on the row exactly as it was proven (digest, owner, principal, not
  revoked). It restarts both deadlines, sets a new rotation id with no previous one, and records the method, the last
  use and the client's description when given; it keeps the guard, owner, principal and creation details. A swap that
  misses reconsiders the sign-in without the device, factor policy included, and creates one; it never retries.
- The guard is bound after the session's transaction, with the usual immediate bind events; `DeviceCreated` (new
  devices only) and `SignedIn` follow the commit on the device's connection and never fire for a rolled-back session.
- The service holds no per-sign-in state, and reads the guard's provider, resolver, dispatcher and request, and the
  sign-in method manager and policies from the container, each time it needs them.

## Success Path

- A new device: `Attempting`, `Validated`, `Login`, `Authenticated`, `PrincipalAssigned`, `DeviceAuthenticated`, then,
  once committed, `DeviceCreated` and `SignedIn` (`deviceCreated: true`). The device's last use is the sign-in, so the
  shipped last-use listener writes nothing more.
- A continued device: the same, without `DeviceCreated`, and `SignedIn` with `deviceCreated: false`.
- `start()`: the same without `Attempting`.

## Failure / Edge Cases

- A required additional factor starts no session: the service stores a pending sign-in (the digest of a single-use,
  guard-bound token's secret, who, as whom, how, from which client, the proven device and the digest it was proven
  against, the windows of the attempt-limit slots the sign-in took, and an expiry from
  `authentication.sign_in.pending_ttl_seconds`) and returns its token. The token is not a JWT, so no guard authenticates
  a request or a refresh with it. The slots stay taken until the pending sign-in completes, and `discard()` uses one up
  without a session (as when its factor fails), so each guess at a factor costs a sign-in attempt and the guesses are
  bounded by the sign-in limits.
- `pending()` finds a live pending sign-in of the guard (identity reloaded through the provider as the recorded owner,
  principal through the hinted path as the recorded one, still owned) without using it up. `complete()` uses it up by a
  `DELETE` on its id, digest and unexpired `expires_at` that only one completion can win, checks it again (method,
  activity, tenant, `admit()` with the stored identifier type; not the factor policy), and writes the session in the
  same transaction; a failed check still uses it up. Every lookup failure is `pending_invalid`. A completion runs in the
  completing request's client: its events and the device's last use carry that client, while a device it creates
  records the client the sign-in came from as its creation.
- Inside a caller's transaction the service's transaction is a savepoint: the guard is bound at once, the lifecycle
  events wait for the caller's commit, and a rollback withdraws them with the device while the guard stays bound. Do not
  roll back around a sign-in.
- A listener that throws on a bind event propagates after the session committed: the device exists, the pair is lost,
  and the lifecycle events are not dispatched.
- A device continued by a sign-in makes the earlier refresh tokens of the device replays (see
  `refresh-rotation-and-replay.md`).
- A crafted client name or platform is stored cleaned (`SignInContext`), so it cannot fail the insert.

## Implementation Anchors

- `src/Sessions/SessionService.php`: `signIn()`, `start()`, `establish()`.
- `src/Sessions/SessionWriter.php`: `create()`, `continueOn()` and the compare-and-swap.
- `src/Sessions/DeviceProof.php`, `src/Jwt/JwtTokenService.php` (`parseRefreshProof()`), `src/Jwt/DeviceLookup.php`.
- `src/Sessions/PendingSignIns.php` and `src/Models/PendingSignIn.php`: issuing, finding and consuming pending sign-ins.
- `src/Sessions/Admission/SignInAdmission.php`, shared with `attempt()`; `src/Guards/PinnedPrincipal.php`.
- `src/Database/AfterCommit.php`, shared with the refresh exchange's revocation report.
- `src/Guards/JwtGuard.php` (`sessions()`), `src/AuthManager.php` (`sessions()`), and the factory
  `AuthenticationServiceProvider::createJwtGuard()` passes the guard.

## Authoritative Tests

- `tests/Feature/Sessions/SessionServiceTest.php`
- `tests/Integration/Sessions/SessionServiceTest.php`
- `tests/Feature/Sessions/DeviceProofTest.php`, `tests/Feature/Sessions/SessionWriterTest.php`
- `tests/Feature/Sessions/PendingSignInsTest.php`, `tests/Integration/Sessions/PendingFactorSessionServiceTest.php`
- `tests/Integration/Sessions/SignInPolicyEndToEndTest.php`: the shipped audience policy, attempt limiter, normalisers
  and verified-identifier gate, through `signIn()`, `start()` and `attempt()`
- `tests/Integration/Migration/PendingSignInsTableSchemaTest.php`
- `tests/Performance/SessionServiceQueryBudgetTest.php`

## Change Triggers

Update this note when any of the following change:

- the order of the checks, or which of them count an attempt or run in the timebox
- what proves a device, or what continuing one writes or keeps
- what the session's transaction contains, or when the guard is bound
- when `DeviceCreated` and `SignedIn` are dispatched, or what they carry
- what reaches the events from the sign-in input
- what a pending sign-in stores, how long it lives, what finds it, or what completing it checks
