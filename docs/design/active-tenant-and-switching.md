# Active Tenant and Switching

## Purpose

This note records which tenant a session acts in and how that is decided, held and changed: the three access contracts
and their defaults, opaque tenant identifiers and the resolver, the checks every bearer request makes against the
session's active tenant, the switch of principal or tenant, and the tenant authentication policy with the helper that
applies a change of it. The switch's own compare-and-swap and retry rule are in `principal-choice-and-switch.md`; a
session held back by the policy waits as `pending-sessions.md` describes; the per-application policy is in
`application-policy.md`.

## Invariants

- A principal belongs to a tenant (`getTenant()`, its own; none for a platform principal); a session acts in one, its
  active tenant, recorded in `tenant_id` as the tenant's identifier stringified (`null` for none). The active tenant is
  the principal's own unless the sign-in, the choice or a switch names another (`TenantSelection::of()`), and every
  token issued for a session names the tenant the session records (`TokenProfile::sessionTenant()`, an
  `InvalidArgumentException` otherwise); a token without a session acts only in its principal's own tenant.
- Three contracts answer the questions the package does not own, each yes or no, each bound `singletonIf` and asked
  inside `WriteConnection::during()` for the principal (and the tenant): `ApplicationAccess::mayUse()` (default
  `AdmitAnyPrincipal`: any principal may use any application), `TenantAccess::mayActIn()` (default `OwnTenantOnly`: a
  principal only in its own tenant, a platform principal only in none, a principal whose tenant cannot be loaded
  nowhere) and `TenantResolver::resolve()` (default `ResolveNoTenant`: no identifier names a tenant). The package never
  interprets a tenant tree: an application that lets principals act in other tenants binds both `TenantAccess` and a
  `TenantResolver`, and until it does any other tenant is refused.
- The principal's own tenant is read from the principal and never from the resolver, so the defaults make no resolver
  call; a tenant the resolver returns under another identifier than the one asked is not taken for it
  (`Admission\TenantAdmission`). `TenantAccess` is asked before the tenant's activity is read, so a tenant the
  principal may not act in is `tenant_ineligible` and says nothing of its state; one it may act in that is inactive is
  `tenant_inactive`.
- A principal holds a session only while it is active, its own tenant is active and `ApplicationAccess` lets it use
  the application (`Admission\PrincipalAdmission`: `principal_inactive`, `tenant_inactive`, `principal_ineligible`),
  and only in an active tenant it may act in. Both tenants, its own and the active one, must be active on every path:
  sign-in, the choice, refresh, switch and bearer.
- A bearer token naming a session is checked against the row already loaded, in order, after the session's own checks
  (`OwnedSession::refusal()`): its `tenant_id` must be the session's (`session_tenant_mismatch`), its principal the
  session's (`session_principal_mismatch`), its `iat` no earlier than `switched_at` (`session_switched`), and the
  active tenant still active (`tenant_inactive`): the principal's own, already read, is not read again, and any other
  is resolved once. No access contract and no tenant policy is asked per request.
- `Auth::tenant()` is the active tenant the guard bound with the request's admission, held as guard state and cleared
  with it, so it never outlives the request under Octane. A trusted bind with a session takes the tenant the session
  records, unchecked (an inactive one included); one without takes the principal's own. A tenant such a bind cannot
  load (no longer resolving, or the principal's own deleted) makes `Auth::tenant()` throw `TenantUnavailableException`,
  and its events carry none, so `null` from `Auth::tenant()` only ever means no tenant.
- A switch names its destination with a `SwitchTarget` (another principal of the identity, with its default tenant or
  one named; or another tenant for the principal the session records). It admits the destination as a sign-in would,
  asks the destination tenant's policy, and rotates the session in place with one compare-and-swap that moves
  `switched_at` when the principal or the tenant changed, so every access token from before the change is refused at
  once. `PrincipalSwitched` reports both changes (`principalChanged`, `tenantChanged`, the tenant left) and fires only
  when something changed.
- A tenant's authentication policy (`TenantAuthenticationPolicy::requirementFor()`, default `RequireNothingOfTenants`)
  answers a `TenantRequirement`: a further factor (a `Requirement`), the connections the session must have been
  established through (`null` for no requirement, `[]` for none that satisfies), and a version. It is asked inside
  `WriteConnection::during()` for the tenant, with the application, identity, principal, session and a lazy
  `connectionId()` (the connection the session was established through, found when the policy or the judgement first
  asks, and once: `TenantPolicyContext`), so exemptions are its own answer; a destination of no tenant
  has no policy and asks nothing.
- `TenantPolicyCheck::check()` judges a session, or a sign-in about to write one, against that answer: `SSO_REQUIRED`
  when it names connections the session was not established through (the provenance's connection), else
  `FACTOR_REQUIRED` when the one judge (`Requirements\RequirementJudge`) does not find the further factor met, else
  `MET`. The judge asks the bound `ExternalEvidencePolicy` first, for a session an external provider established that
  holds accepted evidence (any of it, the newest first, and each piece must meet the whole requirement), then
  `RequirementCheck::evaluate()`. The evidence is the sign-in's own in memory, or the session's provenance and proofs,
  read only when the answer needs them, so the default policy costs no query, and read current when the session's row is
  held locked (`Requirements\ProofSource`; see `proofs-and-freshness.md`). The defaults (`InsufficientEvidence`,
  `MeetNoRequirement`) meet nothing: a further factor fails closed until an application trusts a provider's evidence or
  a further-factor package binds its check.
- Where it is asked, and what a shortfall does: at sign-in with a selected principal (`sso_required` refuses and writes
  nothing; a factor makes `mfa` outstanding); at the choice (`sso_required` refuses that principal only; a factor
  records it and waits on `mfa`); at activation (either refuses, the session left pending); at every refresh (a
  connection revokes the session as `tenant_policy_changed` and refuses as `sso_required`; a factor returns it to
  pending); at a switch (a connection refuses and changes nothing; a factor returns it to pending with the destination
  recorded); at `attempt()`, which cannot wait (`sso_required` or `additional_factor_required`); and when
  `Auth::caller()` reads a refresh credential, which cannot wait either and writes nothing (the same two reasons). Never
  on a bearer request.
- The version answered is recorded on the session (`tenant_policy_version`) at activation, at a refresh and at a switch,
  and is part of the refresh's and the switch's compare-and-swap, so a version written by the helper in between makes
  them judge the session again.
- `tenantPolicyChanged($tenant)` applies a change at once and outside any request: every live session (unrevoked, before
  both deadlines) acting in the tenant, on every guard, pending ones included, is locked first, its key read in key
  order a chunk at a time with a locking read, and only then read again by key, a chunk at a time, and judged, its
  proofs and provenance read current, so every session row is locked before any proof row; all in one transaction on the
  session model's connection (a savepoint inside a caller's transaction there). A session recorded at the very version
  answered, neither `null`, is skipped; an active one that falls short is revoked (`tenant_policy_changed`) and one that
  meets it records the version; a pending one is revoked only when it would need another connection, since its
  activation judges a further factor itself. Each revocation is one conditional update on the session still acting in
  the tenant and unrevoked, reported by `SessionRevoked` once committed.
- `tenantDeactivated()` ends every session acting in the tenant, whatever its principal, as well as the sessions of the
  principals listed for it, each session counted once.

## Success Path

1. A sign-in selects one principal and no tenant: the session records the principal's own tenant, and its tokens name
   it. `Auth::tenant()` on a bearer request is that tenant, with no resolver call.
2. The application binds a `TenantAccess` and a `TenantResolver` that let a principal act in the tenants below its own.
   `switchTo($presented, SwitchTarget::tenant(TenantSelection::of($id)), $client)` admits the descendant, asks its
   policy, and rotates the session into it: the old access token is refused as `session_tenant_mismatch`, and the new
   one acts in the descendant.
3. The descendant's policy starts to require a further factor, and the application calls `tenantPolicyChanged()` inside
   the transaction that publishes it: the session, which lacks the factor, is revoked as `tenant_policy_changed` with
   the publication, and `SessionRevoked` follows its commit.

## Failure / Edge Cases

- A tenant the resolver cannot find, or one `TenantAccess` refuses, is `tenant_ineligible` wherever it is selected; a
  recorded tenant that no longer resolves is `tenant_inactive` on refresh and on the bearer path.
- Two context changes in one second move the floor one second past the recorded one (`SwitchFloor::after()`): no token
  from before the second change is accepted, and its own tokens are refused until the client refreshes after that
  second.
- A policy published while a sign-in is in flight: a session that enters the tenant after the helper's scan, having
  read the old policy, is judged at its first refresh, which always asks the policy, so the window is at most one
  access-token lifetime. For a strict cut-off, call the helper again once the publishing transaction commits; it is
  idempotent, skipping every session it recorded at the new version.
- A `null` version is never taken as already checked: the helper judges every session whose recorded or answered
  version is `null`.
- A switch that races the helper either wins (the helper's conditional revocation then finds the session acting
  elsewhere and leaves it) or loses its compare-and-swap and is judged again.

## Implementation Anchors

- `src/Contracts/ApplicationAccess.php`, `src/Contracts/TenantAccess.php`, `src/Contracts/TenantResolver.php` and
  their defaults `src/Applications/AdmitAnyPrincipal.php`, `src/Tenancy/OwnTenantOnly.php`,
  `src/Tenancy/ResolveNoTenant.php`.
- `src/Admission/PrincipalAdmission.php` (`refusal()`, `refusalOfActive()`, `mayUse()`),
  `src/Admission/TenantAdmission.php` (`select()`, `recorded()`), `src/Tenancy/TenantSelection.php`.
- `src/Guards/BearerAuthentication.php`: `onSession()`; `src/SessionRecords/OwnedSession.php`: `actsIn()`;
  `src/Guards/Concerns/BindsContextualState.php`: `tenant()`; `src/Jwt/TokenProfile.php`: `sessionTenant()`.
- `src/Sessions/SessionSwitch.php`, `src/Sessions/SwitchTarget.php`, `src/Jwt/RefreshRotationStore.php`
  (`switchSession()`, `contextChanges()`), `src/SessionRecords/SwitchFloor.php`.
- `src/Contracts/TenantAuthenticationPolicy.php`, `src/Contracts/RequirementCheck.php`,
  `src/Tenancy/TenantPolicyCheck.php`, `src/Tenancy/TenantRequirement.php`, `src/Tenancy/RequireNothingOfTenants.php`,
  `src/Requirements/`.
- `src/Sessions/TenantPolicyChanges.php` (behind `tenantPolicyChanged()`), `src/Sessions/RevocationScope.php`
  (`activeTenant()`), `src/Jwt/RefreshTokenExchange.php` (the refresh's policy check).

## Authoritative Tests

- `tests/Feature/Tenancy/AccessContractsTest.php`, `tests/Feature/Tenancy/ActiveTenantTest.php`,
  `tests/Feature/Admission/PrincipalAdmissionTest.php`, `tests/Feature/Admission/TenantAdmissionTest.php`,
  `tests/Integration/Admission/PrincipalAdmissionTest.php`, `tests/Unit/Tenancy/OwnTenantOnlyTest.php`,
  `tests/Unit/Tenancy/ResolveNoTenantTest.php`, `tests/Unit/Tenancy/TenantSelectionTest.php`,
  `tests/Unit/Applications/AdmitAnyPrincipalTest.php`
- `tests/Integration/Guards/BearerAuthenticationTest.php` (the tenant, principal and switch checks on the row)
- `tests/Feature/Sessions/SessionSwitchTest.php` (principal only, tenant only, both, back again, the destination's
  refusals and its policy), `tests/Integration/Sessions/SessionSwitchTest.php`
- `tests/Feature/Sessions/TenantAuthenticationPolicyTest.php`, `tests/Feature/Tenancy/TenantPolicyCheckTest.php`,
  `tests/Unit/Tenancy/TenantRequirementTest.php`, `tests/Unit/Requirements/RequirementTest.php`,
  `tests/Unit/Requirements/RequirementSubjectTest.php`
- `tests/Feature/Sessions/RevocationScopeTest.php` `testATenantsScopeHoldsTheSessionsActingInIt`
- `tests/Feature/Sessions/TenantPolicyChangesTest.php`, `tests/Integration/Sessions/TenantPolicyChangesTest.php` (the
  two passes: every session locked before the first proof read, only the sessions the first pass found judged)
- `tests/Integration/Sessions/CurrentProofReadsTest.php` `testAPolicyChangeCountsAStepUpCommittedMeanwhile`,
  `testAPolicyChangeJudgesAReusedKeyOnItsOwnProvenance`
- `tests/Performance/SessionRevocationQueryBudgetTest.php` `testATenantPolicyChangeIsLinearInTheTenantsSessions`

## Change Triggers

Update this note when any of the following change:

- the access contracts, their defaults, or where and in what order they are asked
- how a tenant is selected, resolved or recorded, or which tenant a token names
- the bearer checks against the session's active tenant, or their order
- what a switch changes, or when `switched_at` moves
- where the tenant authentication policy is asked, or what a shortfall does on each path
- how `tenantPolicyChanged()` or `tenantDeactivated()` choose and end sessions
