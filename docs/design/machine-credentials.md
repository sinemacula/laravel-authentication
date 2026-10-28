# Machine Credentials

## Purpose

This note describes how non-human identities authenticate and what the package guarantees about the scopes their
credentials carry. It is the convention the other packages of the suite follow: this package carries scopes, an
authorization package decides what they allow.

## Invariants

- A scope is an opaque RFC 6749 scope token (printable ASCII other than space, `"` and `\`, at most 255 bytes). The
  package stores scopes as an ordered list without duplicates and never reads meaning into one.
- Scopes are a ceiling, never a permission: an authorization package intersects them with the principal's permissions.
- `Auth::scopes()` is `null` when no credential limits the request (a human identity's session, or nothing bound), the
  credential's granted list for an API key or a client credentials token, and `[]` for a `MachineIdentity` bound
  without a credential: a machine is never left without a ceiling.
- Every bound context's events carry the credential's id (`credentialId`) and its scopes (`scopes`) as plain strings.
- A credential's scopes are fixed when it is issued, after normalisation and the `ScopeRegistry`'s check; a malformed
  or rejected scope is an `InvalidScopeException`, the caller's error rather than a failed authentication.

## Success Path

- An application issues a credential with scopes; the scopes are normalised and the registry is asked which of them
  the principal may not be granted on the guard (`AcceptAnyScope`, the default, rejects none).
- A request authenticated by the credential binds its identity and principal with the credential's scopes;
  `Auth::scopes()` returns them and every contextual event reports them.

## Failure / Edge Cases

- A scope that is not a scope token (empty, spaced, quoted, non-ASCII, too long, not a string) is refused with every
  offending value named; a value that is not a string is named by its type.
- A registry that names a scope it was not asked about cannot widen the refusal: only scopes being granted are refused.
- The trusted binds (`login()`, `setUser()`, `authenticateAs()`) bind a machine as given, with `[]` scopes.

## Implementation Anchors

- `src/Scopes/Scopes.php`: `normalise()`, `parse()`, `format()`, `isSubset()`, `grantable()`.
- `src/Contracts/ScopeRegistry.php`, `src/Scopes/AcceptAnyScope.php`, `src/Exceptions/InvalidScopeException.php`.
- `src/Guards/Concerns/BindsContextualState.php`: `scopes()`, and the scopes a bind without a credential gets.
- `src/Events/EventContext.php`: `credentialId`, `scopes`.

## Authoritative Tests

- `tests/Unit/Scopes/ScopesTest.php`
- `tests/Feature/Guards/BindsContextualStateTest.php`
- `tests/Integration/Facade/AuthScopesIntegrationTest.php`

## Change Triggers

- Any change to the scope-token syntax, to what `Auth::scopes()` returns for a kind of request, or to when the registry
  is asked.
