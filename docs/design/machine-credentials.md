# Machine Credentials

## Purpose

This note describes how non-human identities authenticate and what the package guarantees about the scopes their
credentials carry. It is the convention the other packages of the suite follow: this package carries scopes, an
authorization package decides what they allow.

## Invariants

- A non-human identity implements `MachineIdentity`. It has no password, no interactive sign-in, no device and no
  refresh: `PasswordSignIn` refuses it as `invalid_credentials` before any hash or account count; `SignInAdmission`
  refuses it first, as `machine_identity`, for every method and for `start()`, `complete()` and `choose()`;
  `RefreshAdmission` refuses a device it owns (refresh and switch of principal); `BearerAuthentication` refuses a
  session token naming it; `JwtTokenService` issues it no session token (`LogicException`). The trusted binds stay
  trusted and bind it with `[]` scopes.
- A scope is an opaque RFC 6749 scope token (printable ASCII other than space, `"` and `\`, at most 255 bytes). The
  package stores scopes as an ordered list without duplicates and never reads meaning into one.
- Scopes are a ceiling, never a permission: an authorization package intersects them with the principal's permissions.
- `Auth::scopes()` is `null` when no credential limits the request (a human identity's session, or nothing bound), the
  credential's granted list for an API key or a client credentials token, and `[]` for a `MachineIdentity` bound
  without a credential: a machine is never left without a ceiling.
- Every bound context's events carry the credential's id (`credentialId`) and its scopes (`scopes`) as plain strings.
- An API key is `<prefix>_<public>_<secret>`; only `<prefix>_<public>` and the SHA-256 digest of the secret are stored,
  so the key exists in plaintext only in the `IssuedApiKey` the issuing call returns (whose dump redacts it).
- A key belongs to one guard, one non-human identity, one principal and that principal's tenant. Every keyed operation
  of the service matches the principal's type and identifier, and the guard, in its statement; a key of another
  principal or guard is absent.
- A presented key costs one indexed lookup of its public part on the write connection and a constant-time digest
  comparison, against a fixed digest when no key matched; never a password hash.
- Every write to a key is one conditional statement on its own connection (rotation: a conditional update of the
  replaced key, then the insert of its replacement, in one transaction), and its event is dispatched once committed
  there.
- A credential's scopes are fixed when it is issued, after normalisation and the `ScopeRegistry`'s check; a malformed
  or rejected scope is an `InvalidScopeException`, the caller's error rather than a failed authentication.

## Success Path

- `Auth::apiKeys($guard)->issue($identity, $principal, $scopes)` resolves the principal for the identity through the
  guard's resolver (as a pinned principal), asks the audience to admit it, normalises and registers the scopes, records
  the tenant, draws a public part (again on the unlikely collision with a stored one, at most three times) and a
  secret, inserts the row and returns the key once; `ApiKeyIssued` follows the commit.
- An `api_key` guard request: parse the bearer key, look its public part up, compare digests, check the guard,
  revocation and expiry, that the audience lists `api_key`, then the owner (exactly the recorded identity, a
  `MachineIdentity`, active) and the principal (exactly the recorded one, active, in an active tenant, of the recorded
  type and tenant, admitted by the audience); bind with `Authenticated` and `PrincipalAssigned` only, and record the
  last use at most once per throttle with one conditional update.
- `rotate()` ends the replaced key at `now + overlap` or its own expiry, whichever comes first, with an explicit `CASE`
  (never `LEAST()` over a nullable column), and inserts the replacement with the same binding and scopes.

- An application issues a credential with scopes; the scopes are normalised and the registry is asked which of them
  the principal may not be granted on the guard (`AcceptAnyScope`, the default, rejects none).
- A request authenticated by the credential binds its identity and principal with the credential's scopes;
  `Auth::scopes()` returns them and every contextual event reports them.

## Failure / Edge Cases

- A malformed key, an unknown public part and a wrong secret are all `credential_invalid`; the malformed key costs no
  query. Another guard's key is `credential_guard_mismatch`, a revoked one `credential_revoked`, an expired one (a
  rotated key past its overlap included, from the second its expiry names) `credential_expired`.
- A request is refused with exactly one `AuthenticationFailed` (flow `api_key`), naming the key once its public part
  found one. The guard counts no attempts: the secret cannot be guessed, and counting would put a write on every
  refused request.
- `attempt()` on an `api_key` guard always fails (`method_not_allowed`, flow `sign_in`) without a query: machines have
  no interactive sign-in. `validate(['api_key' => $key])` binds and dispatches nothing.
- Of two concurrent rotations of a key, the second waits on the first's row lock and replaces nothing once it commits
  (or rotates the key itself once it rolls back); a key revoked between a rotation's read and its update is not
  rotated. Two concurrent revocations report the key once.
- A key is not issued for a principal whose tenant cannot be loaded; a revocation or rotation reported after the tenant
  went reports no tenant.

- A scope that is not a scope token (empty, spaced, quoted, non-ASCII, too long, not a string) is refused with every
  offending value named; a value that is not a string is named by its type.
- A registry that names a scope it was not asked about cannot widen the refusal: only scopes being granted are refused.
- The trusted binds (`login()`, `setUser()`, `authenticateAs()`) bind a machine as given, with `[]` scopes.

## Implementation Anchors

- `src/Contracts/MachineIdentity.php`; `src/Sessions/Admission/SignInAdmission.php`,
  `src/Sessions/Methods/PasswordSignIn.php`, `src/Sessions/SessionPreconditions.php`, `src/Jwt/RefreshAdmission.php`,
  `src/Guards/BearerAuthentication.php`, `src/Jwt/JwtTokenService.php`, `src/Jwt/DeviceOwnership.php`.
- `src/Scopes/Scopes.php`: `normalise()`, `parse()`, `format()`, `isSubset()`, `grantable()`.
- `src/Contracts/ScopeRegistry.php`, `src/Scopes/AcceptAnyScope.php`, `src/Exceptions/InvalidScopeException.php`.
- `src/Guards/Concerns/BindsContextualState.php`: `scopes()`, and the scopes a bind without a credential gets.
- `src/Events/EventContext.php`: `credentialId`, `scopes`.
- `src/ApiKeys/ApiKeyService.php`, `ApiKeyToken.php`, `ApiKeyLookup.php`, `ApiKeyAuthentication.php`,
  `ApiKeyAdmission.php`, `CredentialBinding.php`, `ApiKeyRules.php`, `ApiKeySettings.php`.
- `src/Guards/ApiKeyGuard.php`, `src/Models/ApiKey.php`, `database/migrations/2026_04_06_000006_create_api_keys_table.php`.

## Authoritative Tests

- `tests/Feature/Sessions/MachineIdentitySignInTest.php`, `tests/Feature/Jwt/MachineJwtTokenServiceTest.php`
- `tests/Unit/Scopes/ScopesTest.php`
- `tests/Feature/Guards/BindsContextualStateTest.php`
- `tests/Integration/Facade/AuthScopesIntegrationTest.php`
- `tests/Integration/ApiKeys/ApiKeyServiceTest.php`, `tests/Integration/ApiKeys/ConcurrentApiKeyRotationTest.php`
- `tests/Feature/Guards/ApiKeyGuardTest.php`, `tests/Performance/ApiKeyGuardQueryBudgetTest.php`

## Change Triggers

- Any change to the scope-token syntax, to what `Auth::scopes()` returns for a kind of request, or to when the registry
  is asked.
- Any change to the key format, to what a presented key costs, to the order or reasons of the guard's checks, or to
  the binding a key is held to.
