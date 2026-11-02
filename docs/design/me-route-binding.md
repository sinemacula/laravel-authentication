# The `me` Route Binding

## Purpose

This note records how a route parameter of a session, identity or principal model binds `me` to the caller's own
instance, how every other value is held to the caller, and which credential a route reads its caller from. It also
covers the two lookups the binding shares its rules with: one session (`SessionService::session()`) and one principal
(`SessionService::principal()`).

## Invariants

- The binding is opt-in (`Concerns\ResolvesMeRouteBinding` on the application's models; the shipped session model does
  not use it). The trait overrides `resolveRouteBinding()`, `resolveSoftDeletableRouteBinding()`,
  `resolveChildRouteBinding()` and `resolveSoftDeletableChildRouteBinding()`, each handing Eloquent's own lookup to
  `Routing\MeBinding` as a closure, so custom keys, `withTrashed()` and scoped bindings keep working.
- The model's kind decides what `me` means: a `Contracts\Session` is a session; else an `Identity` (one that is its own
  principal included) is an identity; else a `Principal` is a principal; anything else is a `LogicException`.
- A route reads the access credential of its guard (the default guard, which `auth:<guard>` sets) unless it declares the
  refresh credential (`authentication.refresh[:<guard>]`, `UseRefreshCredential`) or the pending credential for a
  pending action (`authentication.pending:<action>[,<guard>]`, `UsePendingCredential`). The middleware record the
  declaration on the request (`Routing\DeclaredCredential`, which validates the action; a second, different declaration
  is a `LogicException`) and make a named guard the default, nothing else. The credential is never inferred from what a
  request carries, so a refresh cookie that rides on every request cannot turn a read route into one a refresh token
  authenticates. The provider orders both before `SubstituteBindings` in the kernel's middleware priority once the
  kernel is resolved, so the declaration is in place before any parameter binds.
- The caller (`Routing\CallerCredentials`) is read only when a binding asks, and at most once per request for a guard, a
  credential and an action: it is kept on the request's attributes under that key, so several bound parameters read the
  credential once, a guard changed later in the request is read afresh, and nothing outlives the request (no static
  state; Octane-safe).
  - access: the guard must be a package `ContextualGuard` (else `LogicException`); its identity, principal, active
    tenant and session (none for an access-only token or an API key). The guard reports its own failures.
  - refresh: `SessionService::refreshCredentialFromRequest()`, which reads the guard's transport (cookie or body),
    proves and admits the token as a refresh would, without rotating it (`refresh-token-transport.md`), and judges the
    session against its tenant's authentication policy as a refresh does, writing nothing: `sso_required` for a session
    the next refresh would revoke, `additional_factor_required` for one it would return to pending. A replayed token
    revokes its session as `rotation_reuse`, as every path that accepts a refresh token does, so a read route behind
    `authentication.refresh` can revoke a session.
  - pending: the `session.pending_credential_field` body field (JSON or form body, never the query string or a header),
    named by `pending()`, and the session must allow the declared action now (the first outstanding requirement's
    actions).
  - A refresh or pending credential the request carries and that is refused is reported once, by `AuthenticationFailed`
    (flow `refresh` with the refresh's reason; flow `sign_in` with `pending_invalid` or `pending_action_not_allowed`),
    never the credential. A request that carries none is not reported.
- `me`: the caller's instance of the model's kind (its identity, session or principal), provided it is an instance of
  the model's class; none (no caller, a session-less credential for a session, a pending session still to choose for a
  principal) is an `AuthenticationException` with the guard, a JSON `401`.
- Any other value: no caller finds nothing; otherwise Eloquent's lookup runs inside `WriteConnection::during()`, so the
  query and its eager loads read the writer, and what it finds must agree with the credential, else `null` (a `404`):
  - an identity: the caller's (same class and identifier);
  - a session: owned by the caller's identity (`SessionOwnership::isOwner()`), and with a refresh or pending credential
    the very session that credential proves (D13, D19); with the access credential any session of the identity, so a
    screen can revoke another one;
  - a principal: the one the caller acts as; one its identity may use the application as (`principal()` below, with the
    identifier type the session's sign-in used; on a guard without sessions, an API key guard, only the current
    principal); or, with a pending credential, the one the pending session records or one it offers for the choice.
- A child binding of a parent with the trait: when the child's model uses the trait too, it resolves as a top-level
  binding through the parent's relationship, and a `me` child must also be within that relationship (an `exists` on the
  writer); otherwise the parent's own method runs unchanged. A child of a parent without the trait never reaches the
  package (Laravel asks the parent).
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

- `GET /sessions/me` behind `auth:api`: the session the bearer is bound to, no query added to the request's own.
- `POST /auth/sessions/me` behind `authentication.refresh:browser`, under the browser application's cookie path
  (`/auth`), where the browser sends the cookie: the session the refresh cookie proves, proven once however many
  parameters say `me`.
- `POST /sign-in/principals/{membership}` behind `authentication.pending:choose_principal,api`: a membership the pending
  session offers.

## Failure / Edge Cases

- The trait reserves `me` as a value of every parameter its model binds, and binds only the caller's own instances: an
  administrator's route that binds other identities' instances uses `Route::bind()` or a model without the trait.
- An authenticated caller's own instance is never soft-deleted (the provider, the resolver and the session lookup all
  apply the scope), so a `me` child needs no `withTrashed()` rule of its own.
- An application that replaces the kernel's priority list after it is resolved, or one without `SubstituteBindings` in
  it, must order the credential middleware before `SubstituteBindings` itself.
- A route on a guard that is not one of the package's is a `LogicException`; an unknown pending action is an
  `InvalidArgumentException`; a malformed `session.pending_credential_field` is an `InvalidArgumentException`, which
  `authentication:check` reports.

## Implementation Anchors

- `src/Concerns/ResolvesMeRouteBinding.php`; `src/Routing/MeBinding.php`, `src/Routing/CallerCredentials.php`,
  `src/Routing/Caller.php`, `src/Routing/DeclaredCredential.php`, `src/Routing/Enums/CallerCredential.php`
- `src/Http/Middleware/UseRefreshCredential.php`, `src/Http/Middleware/UsePendingCredential.php`;
  `src/AuthenticationServiceProvider.php` (`registerMiddleware()`)
- `src/Sessions/Concerns/LooksUpSessions.php`, `src/Sessions/ActiveSessions.php` (`find()`),
  `src/Sessions/PendingEvaluation.php` (`principal()`), `src/Sessions/PendingState.php` (`credentialField()`),
  `src/Http/RequestBody.php`
- `src/Sessions/SessionRefresh.php` (`credentialFromRequest()`), `src/Sessions/RefreshCredential.php`

## Authoritative Tests

- `tests/Feature/Routing/MeBindingTest.php`: `me` and explicit ids for each credential and kind, the refresh cookie,
  scoped children, soft deletes, the JSON `401`, one report per request
- `tests/Feature/Routing/CallerCredentialsTest.php`, `tests/Feature/Routing/ResolvesMeRouteBindingTest.php`,
  `tests/Feature/Routing/ApiKeyMeBindingTest.php`, `tests/Unit/Routing/DeclaredCredentialTest.php`
- `tests/Feature/Http/Middleware/UseRefreshCredentialTest.php`,
  `tests/Feature/Http/Middleware/UsePendingCredentialTest.php`, `tests/Feature/AuthenticationServiceProviderTest.php`
  `testTheCredentialMiddlewareAreAliasedAndOrderedBeforeSubstituteBindings`
- `tests/Integration/Routing/ReplicaMeBindingTest.php`
- `tests/Feature/Sessions/LooksUpSessionsTest.php`, `tests/Feature/Sessions/ActiveSessionsTest.php`,
  `tests/Feature/Sessions/PendingEvaluationTest.php`, `tests/Integration/Sessions/ReplicaSessionListingTest.php`,
  `tests/Integration/Applications/ReplicaChoicesAcrossConnectionsTest.php`
- `tests/Performance/MeBindingQueryBudgetTest.php`, `tests/Performance/PrincipalLookupQueryBudgetTest.php`,
  `tests/Performance/SessionListingQueryBudgetTest.php`

## Change Triggers

Update this note when any of the following change:

- what `me` binds for a kind, or what an explicit id must agree with
- which credentials a route may declare, how it declares them, or where they sit in the kernel's priority
- how the caller is read, memoised or reported
- how one session or one principal is looked up, or what makes the lookup and its list differ
