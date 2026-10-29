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
  session token naming it; `JwtTokenService` issues it no session token (`LogicException`). It is never sent a one-time
  code, `Auth::codes()->sendVerification()` and `verify()` refuse it, and it can own no passkey
  (`InvalidArgumentException` from every passkey call that names an owner); a code it holds anyway, or a passkey whose
  owner became a machine, is refused at admission. The trusted binds stay trusted and bind it with `[]` scopes.
- A scope is an opaque RFC 6749 scope token (printable ASCII other than space, `"` and `\`, at most 255 bytes). The
  package stores scopes as an ordered list without duplicates and never reads meaning into one. The list, written
  space-separated, is at most 8,192 bytes (`Scopes::MAX_LIST_LENGTH`), else `InvalidScopeException` at issue: the JSON
  stored in the `TEXT` column (65,535 bytes on MySQL) then never exceeds about 20 KB even with every `/` escaped, and
  an insert that ignores duplicate keys, which on MySQL turns every error into a warning, can never cut it short.
- Scopes are a ceiling, never a permission: an authorization package intersects them with the principal's permissions.
- `Auth::scopes()` is `null` when no credential limits the request (a human identity's session, or nothing bound), the
  credential's granted list for an API key or a client credentials token, and `[]` for a `MachineIdentity` bound
  without a credential: a machine is never left without a ceiling.
- Every bound context's events carry the credential's id (`credentialId`) and its scopes (`scopes`) as plain strings.
- An API key is `<prefix>_<public>_<secret>`; only `<prefix>_<public>` (the key's public id, column `public_id`, which
  is also its OAuth client id) and the SHA-256 digest of the secret are stored, so the key exists in plaintext only in
  the `IssuedApiKey` the issuing call returns, which holds it as a `SensitiveParameterValue` read through `key()`, so
  no dump shows it and serialising it throws. The exchange holds a presented client secret the same way.
- A key belongs to one guard, one non-human identity, one principal and that principal's tenant, each of the last three
  recorded by type (morph class, else class name) and identifier, so a tenant of another type under the same
  identifier is not the key's. Every keyed operation of the service matches the principal's type and identifier, and
  the guard, in its statement; a key of another principal or guard is absent.
- A presented key costs one indexed lookup of its public part on the write connection and a constant-time digest
  comparison, against a fixed digest when no key matched; never a password hash.
- A client credentials exchange (RFC 6749 section 4.4) takes a key of a `jwt` guard, its public part as the client id
  and its secret as the client secret, and issues an access token of that guard with no device and no refresh token,
  carrying the key's id (`cid`) and the granted scopes (`scope`), living the access lifetime for the principal's type and
  never past the key's expiry. A token with `cid` must carry `scope` and name no device, or `parse()` rejects it. The
  RFC 6749 5.1 response carries `scope` only when the token grants at least one: RFC 6749 3.3 has no empty scope value,
  while the claim is `""` for none.
- A client token is held to its key on every request (decided: reject at once rather than at token expiry): the key,
  read by primary key on the writer, must be the token's guard's, not revoked and not expired, the subject a machine,
  and `CredentialBinding` must hold for the loaded identity, principal and tenant. Revoking the key, or the end of a
  rotation's overlap, ends its tokens at the next request.
- Every write to a key is one conditional statement on its own connection (rotation: a conditional update of the
  replaced key, then the insert of its replacement, in one transaction), and its event is dispatched once committed
  there.
- A keyed operation matches the guard and the principal's type and identifier in the statement and then compares the
  key's recorded ones exactly, since a column's collation, such as MySQL's default `_ci`, can count distinct values like
  `alice` and `Alice`, or guards `api` and `API`, as equal.
- A credential's scopes are fixed when it is issued, after normalisation and the `ScopeRegistry`'s check; a malformed
  or rejected scope is an `InvalidScopeException`, the caller's error rather than a failed authentication. Any answer
  from the registry but `[]` refuses, naming the given scopes it names, or every given scope when it names none as
  given, so a registry that answers with a pattern or its own form of a scope never lets the credential through.

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
  (never `LEAST()` over a nullable column), and inserts the replacement with the same binding and scopes but only the
  expiry the call names: none by default (settled design 6.3), so rotating a key that expires without `expiresAt`
  issues one that never does, as README states.
- An application issues a credential with scopes; the scopes are normalised and the registry is asked which of them
  the principal may not be granted on the guard (`AcceptAnyScope`, the default, rejects none).
- A request authenticated by the credential binds its identity and principal with the credential's scopes;
  `Auth::scopes()` returns them and every contextual event reports them.

## Failure / Edge Cases

- The exchange's request is read only from a form-encoded POST body; a parameter in the query string, repeated or not
  a string is `invalid_request`, as are Basic and body credentials together. No client authentication or malformed
  Basic is `invalid_client`. Request failures are reported as `invalid_credentials` and not counted.
- Every failure to authenticate the client (unknown, wrong secret, revoked, expired, another guard's key, owner or
  principal problems) is `invalid_client` (401, with a Basic challenge for a Basic client), counted per IP address; only
  a principal the audience does not admit is `unauthorized_client`. A guard whose audience does not list
  `client_credentials` answers `unauthorized_client` before looking at the key. A scope not granted is `invalid_scope`,
  not counted. Past its limit an address gets 429 `slow_down` (RFC 8628's registered error). Each failure's
  `AuthenticationFailed` names the client id only when it is a key's public part in form
  (`PresentedClient::reportedId()`), else none: a client that sends its whole key as the id, or swaps id and secret,
  would otherwise put the secret in an event (rule: no event field carries a secret), as the `api_key` guard already
  never names one.
- `client_credentials.per_identifier` (per client id as given) is off by default. A client id is public (RFC 6749 2.2;
  it is the key's public part, shown in summaries and events), so a count on it lets anyone who knows it keep the real
  client out from any address, and it buys nothing against a 238-bit secret, the reason the `api_key` guard counts
  nothing either. An application may still set it, accepting that trade-off.
- A malformed key, an unknown public part and a wrong secret are all `credential_invalid`; the malformed key costs no
  query. Another guard's key is `credential_guard_mismatch`, a revoked one `credential_revoked`, an expired one (a
  rotated key past its overlap included, from the second its expiry names) `credential_expired`.
- A request is refused with exactly one `AuthenticationFailed` (flow `api_key`), naming the key once its public part
  found one. The guard counts no attempts: the secret cannot be guessed, and counting would put a write on every
  refused request.
- Enumeration: an unknown public part and a wrong secret in a well-formed key cost the same one lookup, and a
  malformed key costs none (its form is the caller's to see anyway); all three cost the same digest work (an unknown
  public part or a malformed key is compared against a fixed digest), and the key's status is read only once its secret
  verifies; every client failure of an exchange answers the same `invalid_client` body, and a `slow_down` limit on the
  client id, when set, counts it as given, so an id no key has is limited like one that exists. Neither uses a password
  hasher. Codes and passkeys are held to the same criterion (`one-time-codes.md`, `passkeys.md`).
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
- The trusted binds (`login()`, `setUser()`, `authenticateAs()`) bind a machine as given, with `[]` scopes, or, through
  `authenticateAs()`, the scopes it is given (the testing helpers' `scopes`); scopes for a human are refused.

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
- `src/ClientCredentials/ClientCredentialsExchange.php`, `ClientCredentialsRequest.php`, `ClientCredentialsResult.php`;
  `src/Jwt/MachineTokens.php`, `JwtTokenService::issueClientAccessToken()`, `src/Guards/BearerAuthentication.php`
  (`admitForKey()`), `src/Guards/AuthenticatedBearer.php`.
- `src/Guards/ApiKeyGuard.php`, `src/Models/ApiKey.php`, `database/migrations/2026_04_06_000006_create_api_keys_table.php`.

## Authoritative Tests

- `tests/Feature/Sessions/MachineIdentitySignInTest.php`, `tests/Feature/Jwt/MachineJwtTokenServiceTest.php`,
  `tests/Feature/Codes/MachineCodeSignInTest.php`
- `tests/Unit/Scopes/ScopesTest.php`
- `tests/Feature/Guards/BindsContextualStateTest.php`
- `tests/Integration/Facade/AuthScopesIntegrationTest.php`
- `tests/Integration/ApiKeys/ApiKeyServiceTest.php`, `tests/Integration/ApiKeys/ConcurrentApiKeyRotationTest.php`
- `tests/Feature/ClientCredentials/ClientCredentialsExchangeTest.php`,
  `tests/Feature/Guards/ClientTokenBearerAuthenticationTest.php`, `tests/Performance/ClientCredentialsQueryBudgetTest.php`
- `tests/Feature/Guards/ApiKeyGuardTest.php`, `tests/Performance/ApiKeyGuardQueryBudgetTest.php`

## Change Triggers

- Any change to the scope-token syntax, to what `Auth::scopes()` returns for a kind of request, or to when the registry
  is asked.
- Any change to the key format, to what a presented key costs, to the order or reasons of the guard's checks, or to
  the binding a key is held to.
