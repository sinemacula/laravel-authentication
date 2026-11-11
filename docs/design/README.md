# Design Notes

These notes document the package's security and lifecycle contracts that are easy to miss if you only read the
quick-start material or skim the test suite.

Each note follows the same structure:

- `Purpose`
- `Invariants`
- `Success Path`
- `Failure / Edge Cases`
- `Implementation Anchors`
- `Authoritative Tests`
- `Change Triggers`

The current note set is:

- `guard-lifecycle-and-events.md`: standard Laravel auth events plus the package contextual events, and the exact
  successful event order for `attempt()`, direct `login()`, bearer auth, and refresh.
- `guard-context.md`: the one context a guard's flows run on (its name, provider, resolver, dispatcher, request and
  credential timebox), how a rebind reaches every flow built before it, and what a flow may keep from it.
- `event-model.md`: the context every package event carries as plain values, why an event crosses a queue as it is and
  how a listener loads a model itself, when an event that reports a write is dispatched, and the one failure event.
- `outcomes.md`: how the package's services answer: refusals as values, what `null` and `bool` may mean, the shape of a
  result, throttling as an outcome, and the named exceptions.
- `refresh-rotation-and-replay.md`: why refresh is stateful, how per-session rotation works, the grace window for the
  previous rotation id, and when a replayed refresh token revokes the session (`rotation_reuse`).
- `refresh-token-transport.md`: the refresh transport each application uses (the body or its cookie), why a request
  may carry the token in only one place and only by that transport, the cookie's cross-site checks and name, and how a
  cookie application's results hand back the cookie instead of the token.
- `secrets-and-no-store.md`: which values the package hands out as a `Secret`, what a secret refuses (a string cast,
  JSON, serialising) and shows to a dump, why no object the package builds holds a secret in a plain property, and how
  `SecretResponse` and the `authentication.no-store` middleware keep a response from being stored.
- `token-profile.md`: the claims each token carries, the header type that tells access and refresh tokens apart, the
  subject type that tells a person's token from a machine's, what every parse checks, and what the bearer path does not
  read.
- `fail-closed-pid-did.md`: why the `principal` and `sid` claims are commitments a token must prove.
- `storage.md`: where the package's tables live, why the session-backed ones share one connection, and how the models
  and the published migrations choose the same one.
- `access-only-mode.md`: the supported bearer-only, no-sessions migration path.
- `guard-bound-tokens.md`: the `client_id` claim that ties every token to its issuing guard, and the provider-scoped
  owner reload on refresh.
- `session-service.md`: how a guard's session service signs in, creates a session and revokes the one a client proved,
  issues the first pair, and reports it.
- `session-record.md`: what the package calls the record it keeps per sign-in and why, the Laravel names it meets, the
  `sid` claim it keeps, what proves a previous session for replacement, the `superseded` reason, and the sessions
  table's index names.
- `session-lifecycle.md`: which sessions are active, how an identity's sessions are listed, how a session signs out (by
  its access token, or by its refresh credential once the access token has expired) and sessions are revoked (one,
  every session of an identity or a principal, and on security changes, by method or optional listener), and when ended
  sessions are pruned.
- `callers.md`: how the package reads who a request is from the credential its route declares, how it judges whether a
  session, identity or principal is the caller's, and the one-session and one-principal lookups it shares its rules
  with; route bindings are the application's.
- `pending-sessions.md`: how a session waits for the further factor or the choice of principal its sign-in still owes,
  the credential that acts on it and the actions it allows, how it activates, and how an active session returns to
  pending.
- `principal-choice-and-switch.md`: how a sign-in that names no principal waits for the identity to choose one, and how
  a session switches to another principal or active tenant in place, proven by its refresh token.
- `active-tenant-and-switching.md`: which tenant a session acts in, the access contracts that decide it and their
  defaults, the bearer checks against it, the switch, and the tenant authentication policy with the helper that
  applies a change of it.
- `application-policy.md`: what each application (a guard) decides about its sessions (methods and machine credentials,
  none until it lists them; verified identifiers; the principals it admits; lifetimes), where every path enforces it,
  and how the attempt limits and identifier normalisers meet it.
- `one-time-codes.md`: how one-time codes are bound, stored, issued, checked and delivered, why a request for one looks
  the same for an identifier no one has, and who a code is ever sent to.
- `passkeys.md`: how a guard's passkeys are registered, used to sign in usernameless and verified as a further factor,
  the single-use challenges, the relying party they are scoped to, and the sign counter rule.
- `passwords.md`: the password policy and its breached-password seam, the one helper a registration, a change and a
  reset set a password through, what each flow ends, why password reset is not Laravel's broker, and how a reset spends
  its link's token or code with the new password and the revocation.
- `machine-credentials.md`: how non-human identities authenticate, and the scope convention the suite follows: scopes
  carried, never interpreted, and held to an optional registry when a credential is issued.
- `proofs-and-freshness.md`: the proofs a session records and its provenance, how `auth_time` and `amr` are derived
  from them, how a session steps up and reauthenticates in place, how another package reads an active session's proofs,
  and how freshness is judged for a sensitive operation on the proof that meets it.
- `authentication-context.md`: what `Auth::context()` answers for a policy's conditions, built from what the guard
  validated and the session's proofs, held while the bound state is unchanged and forgotten when a proof changes, the
  package's keys and the additional verification recorded on a proof, and the contributors that add keys under a
  namespace of their own.
- `external-sign-in.md`: how a result an external identity provider verified signs in, only through the link contract
  the application binds, what the session records of how it began, how it reauthenticates through the very link that
  established it with the session's row locked last, and how a link's sessions end when it is removed or its scope
  widened.
- `identifier-changes.md`: how an identity's email address or phone number is replaced once the new one is proven,
  after a recent authentication, unique on its normalised value under a race, invalidating the proofs it outdates.
- `provider-composition.md`: why every binding the provider makes is a default another provider's binding is never
  replaced by, in either order, and why the package owns the `auth` binding and what it takes over from the manager it
  replaces.
- `testing-helpers.md`: how a test acts as an identity, principal or session on a package guard, how that survives the
  requests it sends and ends on a sign-out, what the bound-context assertions compare, and the fakes.

These documents are secondary to the code and tests. If a note and a cited test disagree, the test is authoritative.
