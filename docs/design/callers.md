# The Caller of a Request

## Purpose

This note records how the package reads who a request is (`Auth::caller()`), from which credential a route
authenticates with, and how it judges whether a session, identity or principal model is the caller's
(`Caller::owns()`). It also covers the two lookups that judgement shares its rules with: one session
(`SessionService::session()`) and one principal (`SessionService::principal()`). Route bindings, and the keyword a route
uses for the caller's own instance, are the application's: the package binds no route parameter and reserves no value.

## Invariants

- A route authenticates with the access credential of its guard (the default guard, which `auth:<guard>` sets) unless
  it declares the refresh credential (`authentication.refresh[:<guard>]`, `UseRefreshCredential`) or the pending
  credential for a pending action (`authentication.pending:<action>[,<guard>]`, `UsePendingCredential`). The middleware
  record the declaration on the request (`Callers\DeclaredCredential`, which validates the action; a second, different
  declaration is a `LogicException`) and make a named guard the default, nothing else. The credential is never inferred
  from what a request carries, so a refresh cookie that rides on every request cannot turn a read route into one a
  refresh token authenticates. The provider orders both before `SubstituteBindings` in the kernel's middleware priority
  once the kernel is resolved, so the declaration is in place before any parameter binds.
- `Auth::caller()` (`AuthManager::caller()`, `Callers\CallerCredentials`) reads the request being served, as the guards
  do, only when it is asked, and at most once per request for a guard, a credential and an action: the caller is kept
  in one request attribute under that key, so asking again reads the credential once, a guard changed later in the
  request is read afresh, and nothing outlives the request (no caller held in static state; Octane-safe). An access
  caller is kept with its guard's `GuardBinding::boundStateVersion()`, which any bind, switch, sign-out or new request
  replaces, so it is read again after one. A refresh or pending caller is proven from the request itself and kept for
  the request. `AuthManager::forgetGuardState()` forgets every caller on the current request before each queued job.
  - access: the guard must be a package `ContextualGuard` (else `LogicException`); its identity, principal, active
    tenant and session (none for an access-only token or an API key). The guard reports its own failures. Its
    `scopes` are the guard's `scopes()`: an API key's granted list, or a client-credentials token's validated list
    (`[]` for none), and `null` for a human's access token, which no credential limits.
  - refresh: the guard's transport's `extract()` and, once it answered something, the request's `ClientContext`,
    handed to `SessionService::refreshCredential()`, which judges the token on that client (cookie or body),
    proves and admits the token as a refresh would, without rotating it (`refresh-token-transport.md`), and judges the
    session against its tenant's authentication policy as a refresh does, writing nothing: `sso_required` for a session
    the next refresh would revoke, `additional_factor_required` for one it would return to pending. A replayed token
    revokes its session as `rotation_reuse`, as every path that accepts a refresh token does, so a read route behind
    `authentication.refresh` can revoke a session.
  - pending: the `session.pending_credential_field` body field (JSON or form body, never the query string or a header),
    named by `pending()`, and the session must allow the declared action now (the first outstanding requirement's
    actions).
  - A refresh or pending caller's `scopes` are `null`: it is not a general access caller, and scopes do not apply to it.
  - A refresh or pending credential the request carries and that is refused is reported once, by `AuthenticationFailed`
    (flow `refresh` with the refresh's reason; flow `sign_in` with `pending_invalid` or `pending_action_not_allowed`),
    never the credential. A request that carries none is not reported.
- `Caller::owns()` judges the model as it is given, by class and key, and reads nothing but a principal's admission:
  - a session: of the caller's guard, owned by the caller's identity (`SessionOwnership::isOwner()`), and with a refresh
    or pending credential the very session that credential proves (D13, D19); with the access credential any session of
    the identity and guard, so a screen can revoke another one; a session model that is not an `EloquentSession` is not;
  - an identity: the caller's (same class and identifier);
  - a principal: the one the caller acts as; or, with a pending credential, one the pending session offers for the
    choice; or, with any other credential on a guard that keeps sessions, one its identity may use the application as
    (`principal()` below, with the identifier type the session's sign-in used), read on the writer; on a guard without
    sessions, an API key guard, only the current principal;
  - any other model is not the caller's.
- The application looks the model up itself, on the write connection (`WriteConnection::query()` or `during()`), so a
  row the primary has revoked or deleted is never judged from a lagging replica.
- `session($identity, $id)` (`Sessions\Concerns\LooksUpSessions`, `ActiveSessions::find()`) answers the very
  `SessionSummary` the list gives for that session, `current` marked the same way, or `null` when it is not the
  identity's, not active (pending, revoked, past a deadline) or not found; one query through the identity's `sessions()`
  relation on the writer with the list's rule, and none for an id that cannot be a key of the session model
  (`SessionKeyShape`).
- `principal($identity, $id, $identifierType)` (`PendingEvaluation::principal()`) reads the very candidates
  `principals()` reads (the identity's `principals()` on the writer, or the resolver's default for an identity that is
  its own principal or has none), keeps the one whose principal identifier matches (two matches are ambiguous and
  `null`), and admits it as the list admits it (`PrincipalAdmission::refusal()`, after the identifier-type refusal), so
  it is found exactly when the list holds it. The resolver's hinted lookup is never used: a resolver may answer it
  differently from the list.

## Success Path

- Behind `auth:api`, an application's own binding answers its keyword with `$caller->session`, no query added to the
  request's own, and any other id with the session it finds on the writer when `owns()` says it is the caller's.
- Behind `authentication.refresh:browser`, under the browser application's cookie path (`/auth`), where the browser
  sends the cookie: the caller is the session the refresh cookie proves, proven once however often it is asked for.
- Behind `authentication.pending:choose_principal,api`: a membership the pending session offers is the caller's.

## Failure / Edge Cases

- No caller (a guest, a refused refresh or pending credential) is `null`; the application decides what that answers,
  and an `AuthenticationException` on a package guard is a JSON `401`.
- An application that replaces the kernel's priority list after it is resolved, or one without `SubstituteBindings` in
  it, must order the credential middleware before `SubstituteBindings` itself.
- A route on a guard that is not one of the package's is a `LogicException`; an unknown pending action is an
  `InvalidArgumentException`; a malformed `session.pending_credential_field` is an `InvalidArgumentException`, which
  `authentication:check` reports.

## Implementation Anchors

- `src/AuthManager.php` (`caller()`); `src/Callers/Caller.php`, `src/Callers/CallerCredentials.php`,
  `src/Callers/DeclaredCredential.php`, `src/Callers/Enums/CallerCredential.php`
- `src/Http/Middleware/UseRefreshCredential.php`, `src/Http/Middleware/UsePendingCredential.php`;
  `src/AuthenticationServiceProvider.php` (`registerMiddleware()`)
- `src/Sessions/Concerns/LooksUpSessions.php`, `src/Sessions/ActiveSessions.php` (`find()`),
  `src/Sessions/PendingEvaluation.php` (`principal()`), `src/Sessions/PendingState.php` (`credentialField()`),
  `src/Http/RequestBody.php`
- `src/Sessions/SessionRefresh.php` (`credential()`), `src/Sessions/Concerns/RefreshesSessions.php`
  (`refreshCredential()`), `src/Sessions/RefreshCredential.php`, `src/Sessions/PendingCredential.php` (`extract()`)

## Authoritative Tests

- `tests/Feature/Callers/CallerCredentialsTest.php`: each credential's caller, one read and one report per request,
  an access caller read again once its guard's state changes, a refresh caller kept across a bind, the bearer's and the
  API key's admission;
  `tests/Integration/Process/QueueWorkerGuardStateTest.php` `testEachJobReadsItsOwnCaller`
- `tests/Feature/Callers/CallerTest.php`: what `owns()` holds for each credential and kind;
  `tests/Feature/Callers/CallerRouteBindingTest.php`: the guide's application binding over HTTP;
  `tests/Feature/AuthManagerTest.php` `testCallerReadsTheRequestBeingServed`;
  `tests/Unit/Callers/DeclaredCredentialTest.php`
- `tests/Feature/Http/Middleware/UseRefreshCredentialTest.php`,
  `tests/Feature/Http/Middleware/UsePendingCredentialTest.php`, `tests/Feature/AuthenticationServiceProviderTest.php`
  `testTheRouteMiddlewareAreAliasedAndOrderedInThePriority`
- `tests/Integration/Callers/ReplicaCallerTest.php`
- `tests/Feature/Sessions/LooksUpSessionsTest.php`, `tests/Feature/Sessions/ActiveSessionsTest.php`,
  `tests/Feature/Sessions/PendingEvaluationTest.php`, `tests/Integration/Sessions/ReplicaSessionListingTest.php`,
  `tests/Integration/Applications/ReplicaChoicesAcrossConnectionsTest.php`
- `tests/Performance/CallerQueryBudgetTest.php`, `tests/Performance/SessionSignOutQueryBudgetTest.php`,
  `tests/Performance/PrincipalLookupQueryBudgetTest.php`, `tests/Performance/SessionListingQueryBudgetTest.php`

## Change Triggers

Update this note when any of the following change:

- what makes a session, identity or principal the caller's
- which credentials a route may declare, how it declares them, or where they sit in the kernel's priority
- how the caller is read, memoised or reported
- how one session or one principal is looked up, or what makes the lookup and its list differ
