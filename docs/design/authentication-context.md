# Authentication Context

## Purpose

This note records what `Auth::context()` answers: the authentication context of the request being served, in plain
values, for an authorisation policy's conditions. It covers where the context comes from, how long it is held and what
forgets it, the package's keys and how a contributor adds its own, and what it never does. The package decides no
permission: a policy that reads the context is the application's.

## Invariants

- `Auth::context()` (`AuthManager::context()`) answers what the bound `Contracts\AuthenticationContexts` answers. The
  default, `Context\GuardAuthenticationContexts` (bound if nothing else is), holds nothing: on every call it resolves
  the auth manager from the container serving now (the request's sandbox under Octane) and asks its default guard, the
  one Laravel's `auth` middleware made the default for the route (`auth:admin,api` gives the context of whichever guard
  authenticated). A guest, an identity bound without a principal and a guard that is not a package `ContextualGuard`
  give `null`. An application that rebinds the contract answers for itself.
- The context lives on the guard, beside its bound state (`Guards\Concerns\HoldsAuthenticationContext`), never in
  `GuardContext`, a singleton or a static, so it lives no longer than the bound state. It is built on the first
  `authenticationContext()` after the bound state last changed and held while that state is unchanged: "once per
  request" means once per unchanged authentication state.
- What forgets it: `clearContextualState()` (every bind, `logout()`, `forgetUser()`, `forgetSession()`,
  `forgetIdentity()`, `setRequest()` and so every new request and every queued job through `forgetGuardState()`),
  `setPrincipal()` and `setSession()`. `setUser()` clears the previous state before it binds, so a context or credential
  kind from the binding it replaces never survives it. A flow that changes a session's proofs forgets it too, once the
  change commits on the session's connection, and also once it rolls back (`Context\ContextForgetting::onSettle()`),
  since a context built inside the transaction after the change read proofs that never committed: a step-up, a password
  or external reauthentication (`ProofIssuance::issue()`), a satisfied further factor (`PendingSessions::satisfy()`) and
  a voided proof (`FactorRevocations`, also when the session stays active). A voided proof is forgotten at once as well
  (`ContextForgetting::now()`), since a held context would otherwise keep reporting `mfa` and the step-up time of a
  factor whose proofs no longer count in the rest of the factor package's transaction. It asks only the package guards
  already resolved under the names in `auth.guards` (`AuthManager::resolvedGuard()`, which creates no guard and resolves
  no request), and each forgets its context only when its bound session is that session
  (`GuardBinding::forgetAuthenticationContext()`).
- It is built from what the guard validated, never from input and never from a token's claims
  (`Context\ContextBuilder`): the bound identity, principal, active tenant (`tenant()`, so a tenant a trusted bind
  cannot load throws `TenantUnavailableException` as `Auth::tenant()` does), session, credential kind and scopes, the
  guard's name, and the client address of the guard's request as Laravel resolves it through the trusted proxies
  (`GuardContext::client()`).
- The proof-derived keys come from one aggregate read on the write connection (`SessionProofs::history()`), so a lagging
  replica cannot hide a step-up just made, and only for an Eloquent session. Without one (an API key, a client
  credentials token, an access-only token, a binding with no session) `amr` is `[]`, `auth_time` and
  `seconds_since_step_up` are `null`, and `mfa`, `recovery_code` and `multifactor` are `false`. The build reads nothing
  else, locks nothing, writes nothing and reports nothing; what a contributor asks of its subject is read when it asks
  (below).
- The credential kind (`Context\Enums\CredentialKind`) is set by the verified bind of the credential the request
  presented (`bindVerifiedContext(..., ?CredentialKind $kind)`): `access_token` for a person's token on a `jwt` guard,
  `client_credentials` for a token a client credentials exchange issued (it names a key), `api_key` on an `api_key`
  guard. Every other bind (`login()`, `loginVerified()`, `setUser()`, `authenticateAs()`, `attempt()`, a session service
  sign-in, a refresh, a switch) presents none: `credential` is `null`, and the rest still comes from the bound session.
- The package's keys sit under the reserved `authentication` namespace (`AuthenticationContext::NAMESPACE`):
  `subject_type`, `identity_type` and `identity_id`, `principal_type` and `principal_id`, `tenant_type` and `tenant_id`
  (the active tenant), `application`, `session_id`, `amr`, `auth_time` (Unix seconds), `mfa`, `recovery_code`,
  `multifactor`, `seconds_since_step_up`, `credential`, `scopes` (as `Auth::scopes()`) and `ip`. Types are named as
  `EventContext` names them (`Support\MorphClass::of()`: an Eloquent model's morph class, else its class name) and
  identifiers are strings, so a context and an event about the same request agree.
- `mfa`, `recovery_code` and `multifactor` keep three questions apart (AUTH-3.12). `mfa` is an accepted additional
  verification: an `additional_factor` proof, which is one by definition, or an external proof (a first factor or an
  `external_reauthentication`) whose evidence was accepted for an additional verification or multifactor authentication;
  never counted from `amr` and never a recovery code. `recovery_code` is an accepted recovery code. `multifactor` is an
  accepted evaluation that reported multifactor authentication, exactly when `amr` carries `mfa`.
  `seconds_since_step_up` runs from the newest proof that set `mfa` or `recovery_code`, at sign-in or later, to the
  build, never negative.
- The additional verification is recorded on the proof, not inferred: `ProofWriter` writes the proofs table's
  `additional_verification` column, which `SessionProofs::history()` groups by, as `true` for an accepted further
  factor and `false` for a recovery code whatever the adapter reported, and as
  `Proofs\Evaluation::$additionalVerification` for an external proof, so a proof read back says what the context
  reads. `External\EvidenceAcceptance` sets it for each answer of the evidence contract: multifactor
  `(true, true, true)`, an additional verification `(true, false, true)`, phishing resistance or the lowest level only
  `(true, false, false)`, so evidence accepted only for a level never sets `mfa` or the step-up time. Nothing else
  reads the column: requirement judging, freshness and the token claims are unchanged.
- A contributor adds keys under a namespace of its own. It is registered in code, in a service provider's `boot()`
  (`Context\ContextContributors::register($namespace, $abstract)`), never in configuration, where a later merge could
  overwrite a namespace silently. A namespace is a lower-case letter and then up to 31 lower-case letters, digits or
  underscores, never `authentication`, and taken once: a malformed, reserved or repeated namespace is a
  `LogicException` at registration. The package registers none; `mfa` and `sso` are kept, by documentation only, for
  the further-factor and single sign-on adapters.
- On each build every registered abstract is resolved from the container serving now, in the order registered, so a
  contributor may depend on request-scoped services, and asked once with a `Context\ContributionSubject`: the package's
  keys, the live identity, principal, tenant and session the guard holds, and `provenance()`, the session's external
  provenance read on the write connection, in one query, the first time a contributor asks and never again in that
  build; it carries the provider context the adapter gave at sign-in (`External\ProviderContext`), whose keys are the
  contributing package's own and which the package's own keys never carry. Its answer is its keys without the namespace
  (`/^[a-z][a-z0-9_]{0,63}$/D`), each value `null`, a scalar or an array of them; keys hold no dot, so no key of one
  namespace can collide with another's.
- The subject's `proofs($since, $kinds, $limit)` and `firstFactor()` read the counting proofs and the first factor of
  the session the subject was given, never `Auth::session()` or the request's, by the session service's rule
  (`Sessions\ActiveSessionProofs`, see `proofs-and-freshness.md`) with two differences that keep it to that session: the
  guard is the context's `application`, and the stored row must still be the instance given (its generation and owner,
  `SessionOwnership::isSameSession()`, as for a `Session` given to the service), so a key that now holds another session
  answers nothing. `[]` and `null` without a session or for one that is not an Eloquent session (no query, the session
  model never resolved), and for one no longer the application's live, active session of a person; `proofs()` checks its
  limit (1 to `RequirementSubject::MAX_LIMIT`) first, whatever the session, and reads `$since` as the same instant in
  any time zone. Neither is memoised: each call reads the session's row and then its proofs, locked and read current
  inside a transaction on the session model's connection, so each answer is as of its call. `provenance()` keeps its
  memo, since a session's provenance never changes within a generation.
- The context holds plain values only: no model and no secret, so it can be logged, compared or queued as it is. Its
  constructor is public, for tests, and checks contributed keys as the builder does (`InvalidArgumentException`).
  `get('namespace.key', $default)` gives the default only for an absent key; `has()` is true for a key held with
  `null`; a key without exactly one dot is never held.

## Success Path

- A person's session token: the guard binds the token's identity, principal, active tenant and session with credential
  `access_token`; the first `Auth::context()` reads the session's proofs once and builds `amr`, `auth_time` and the
  verification keys from them; every later ask in the request answers the held context with no query.
- A step-up in the request: the proof commits, `ContextForgetting` has the guard bound to that session forget its
  context, and the next ask reads the proofs again, now with `mfa` set and `seconds_since_step_up` near zero.
- An API key or a client credentials token: the context is built with no query, its scopes the credential's.
- A contributor: `register('sso', SsoContextContributor::class)` in `boot()`; the first build asks it and stores its
  keys under `sso`, read as `get('sso.connection_id')`.

## Failure / Edge Cases

- A refused credential is reported once, by the guard that settles it: building the context reports nothing, and asking
  `Auth::user()`, `Auth::context()`, `Auth::caller()` or `check()` again adds no report.
- A contributor that answers a malformed key or a value that is not plain, or an abstract that is not a contributor, is
  a `LogicException` naming the namespace and key; a contributor that asks for the context being built gets a
  `LogicException` (the guard holds a building flag, cleared in a `finally`); an exception a contributor throws
  propagates: a policy is never judged on part of a context.
- A database error in the proofs read propagates as a server error; nothing is cached past the guard's bound state.
- A context first built inside a transaction after a step-up or reauthentication in it holds proofs that have not
  committed; if the transaction rolls back (at any level, a nested one that had committed into it included), the guard
  forgets it, so the rest of the request is judged on the proofs as they stand, never on one that was rolled back.
  `ProofIssuance` registers the forgetting before it writes the proof, so a context the tenant policy built from the
  proof is forgotten too when that policy then refuses the reauthentication or throws.
- A guard built outside `auth.guards` is never asked to forget a context after a proof change; it forgets it on its next
  bind or request like any other.
- Nothing makes a contributor's `proofs()` and `firstFactor()` agree with the package's own keys: `amr`, `mfa` and the
  rest come from `history()` read before the contributors are asked, and a step-up or a void can commit in between, so
  a contributor can see a step-up `authentication.mfa` does not report. A context snapshot that would make them agree
  is not built; each read is observed when it is made.

## Implementation Anchors

- `src/Context/AuthenticationContext.php`, `src/Context/ContextBuilder.php`, `src/Context/ContextKeys.php`,
  `src/Context/ContextContributors.php`, `src/Context/ContributionSubject.php` (with
  `src/Sessions/ActiveSessionProofs.php` for `proofs()` and `firstFactor()`),
  `src/Context/GuardAuthenticationContexts.php`, `src/Context/ContextForgetting.php`,
  `src/Context/Enums/CredentialKind.php`
- `src/Contracts/AuthenticationContexts.php`, `src/Contracts/AuthenticationContextContributor.php`,
  `src/Contracts/ContextualGuard.php` (`authenticationContext()`), `src/Contracts/GuardBinding.php`
  (`forgetAuthenticationContext()`)
- `src/Guards/Concerns/HoldsAuthenticationContext.php`; `src/Guards/Concerns/BindsContextualState.php`
  (`clearContextualState()`, `setPrincipal()`, `setSession()`); `src/Guards/AbstractGuard.php`
  (`bindVerifiedContext()`, `setUser()`); `src/Guards/JwtGuard.php` and `src/Guards/ApiKeyGuard.php` (the credential
  kind)
- `src/AuthManager.php` (`context()`, `resolvedGuard()`); `src/AuthenticationServiceProvider.php` (the default
  bindings)
- `src/Proofs/ProofHistory.php` (`hasAdditionalVerification()`, `hasRecoveryCode()`, `isMultifactor()`,
  `steppedUpAt()`), `src/Proofs/SessionProofs.php` (`history()`, `provenance()`), `src/Proofs/Evaluation.php`,
  `src/External/EvidenceAcceptance.php`; `database/migrations/2026_04_06_000008_create_authentication_proofs_table.php`
- `src/Sessions/ProofIssuance.php`, `src/Sessions/PendingSessions.php`, `src/Sessions/FactorRevocations.php`: the
  forgetting after commit or rollback; `src/Database/AfterCommit.php` (`runIfRolledBack()`)

## Authoritative Tests

- `tests/Unit/Context/AuthenticationContextTest.php`, `tests/Unit/Context/ContextKeysTest.php`,
  `tests/Unit/Context/ContextContributorsTest.php`,
  `tests/Unit/Context/Enums/CredentialKindTest.php`, `tests/Unit/Support/MorphClassTest.php`
- `tests/Feature/Context/ContextBuilderTest.php`: a session token's context, a step-up read from the proofs and not the
  token, a recovery code kept apart, external evidence counted only when accepted for an additional verification, the
  address through trusted proxies, a trusted bind presenting no credential, contributors and their failures;
  `tests/Feature/Context/ContextBuilderMachineTest.php`: API keys, client credentials tokens, service accounts
- `tests/Feature/Context/GuardAuthenticationContextsTest.php`: the default binding, the guard the `auth` middleware
  authenticated with, nothing held between requests, one report per request
- `tests/Feature/Guards/HoldsAuthenticationContextTest.php`: built once and held, forgotten by every change to the bound
  state, the forgetting scoped to its session, re-entry refused, an unloadable tenant
- `tests/Feature/Context/ContextForgettingTest.php`: a step-up, a reauthentication and an external reauthentication seen
  by the rest of the request, only once committed, a context built inside a transaction that made one forgotten when it
  rolls back, every resolved guard bound to the session forgetting and no other, and a context a tenant policy built
  from a proof it then refused or threw on forgotten; `tests/Feature/Sessions/PendingSessionsTest.php`
  `testASatisfiedFactorIsSeenByTheContextOfAGuardBoundToTheSession`; `tests/Feature/Sessions/FactorRevocationsTest.php`
  `testAVoidedProofIsForgottenFromTheContextAtOnce`
- `tests/Feature/Context/ContributionSubjectTest.php`: the provenance read once, its provider context with it; the
  proofs and first factor of the session given, never the request's, nothing read without an Eloquent session (one that
  declares the contract without being a model included), every session it may not answer for (another application's, a
  machine's and a reused key's included) answering nothing with only the row's read, a time given in any zone, each ask
  read again, a contributor seeing a step-up recorded after the package's keys while `authentication.mfa` stays `false`,
  and the locks inside a transaction; `tests/Feature/Context/ContextBuilderTest.php`
  `testAContributorReportsTheProviderContextUnderItsOwnNamespace`;
  `tests/Integration/Sessions/CurrentProofReadsTest.php` `testASubjectsReadAnswersNothingForAReusedKey`;
  `tests/Performance/ProofQueryBudgetTest.php` `testASubjectsProofReadsReadOnEveryCall`
- `tests/Unit/Proofs/ProofHistoryTest.php`, `tests/Feature/Proofs/SessionProofsTest.php`
  `testTheHistoryReadsWhetherAProofIsAnAdditionalVerification`, `tests/Feature/Proofs/ProofWriterTest.php`
  `testAProofIsRecordedAsAnAdditionalVerificationByItsKind`, `tests/Feature/External/EvidenceAcceptanceTest.php`,
  `tests/Integration/Migration/ProofTablesSchemaTest.php`
- `tests/Feature/AuthManagerTest.php` `testContextAnswersWhatTheBoundAuthenticationContextsAnswer`,
  `testResolvedGuardAnswersOnlyAPackageGuardAlreadyResolved`
- `tests/Integration/Context/ReplicaAuthenticationContextTest.php`: a step-up and a provenance the replica has not seen
- `tests/Integration/Octane/CrossTenantRequestsTest.php`: one worker, many tenants and credentials, each request's
  context its own, a contributor with a scoped dependency given each request's instance
- `tests/Performance/AuthenticationContextQueryBudgetTest.php`,
  `tests/Performance/AuthenticationContextMachineQueryBudgetTest.php`

## Change Triggers

Update this note when any of the following change:

- a key under `authentication`, its value or where it comes from
- what builds, holds or forgets the context, or the flows that forget it after a proof change
- how the additional verification is recorded on a proof or read back
- how contributors are registered, resolved, checked or given the session's provenance, proofs or first factor
- the default `AuthenticationContexts` or the guard it asks
