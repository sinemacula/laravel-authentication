# Passkeys

## Purpose

This note records how a guard's passkeys (WebAuthn credentials) are registered, used to sign in usernameless, verified
as a further factor, listed and removed: the ceremonies, the single-use challenges they answer, the relying party every
passkey is scoped to, the sign counter rule against a cloned authenticator, and what is reported. The cryptographic
checks are `web-auth/webauthn-lib`'s; everything around them (storage, challenges, the counter, the session) is the
package's.

## Invariants

- A guard's relying party (`Passkeys\RelyingParty`) is its `passkeys` block over
  `authentication.passkeys.relying_party`, a key present at guard level winning: `id` a lower-case host name that is
  not an IP address, `name` non-empty (by default `app.name`), `origins` a non-empty list of exact origins, each
  `https://host[:port]` or `http://localhost[:port]`, whose host is the id or a subdomain of it. Anything else, or an
  unknown key, fails closed with an `InvalidArgumentException` naming the guard and the key, on every call (nothing is
  cached). The public suffix list is not consulted: the application must not name a public suffix.
- Every passkey records the relying party id it was registered for, and a guard reads, uses, lists and removes only the
  passkeys of its own id. A passkey is found by the SHA-256 hex digest of its raw credential id (unique across all
  relying parties), since an id of up to 1023 bytes is longer than an index can hold; the id itself is kept in full.
- A passkey belongs to a saved Eloquent identity that is not a `MachineIdentity`, recorded as devices record their
  owner: its morph class and its key as a string. A machine identity is refused with an `InvalidArgumentException`
  (it has no interactive sign-in), an identity that is not a model or has no key with a `LogicException`.
- Every ceremony's options carry 32 random bytes as the challenge, require user verification, and are stored with the
  challenge in `passkey_challenges`, bound to the purpose (`register`, `sign_in`, `factor`), the guard, the relying
  party id and, for a registration or a factor, the identity. An answer uses the challenge up with one conditional
  `DELETE` matching all of them and `expires_at > now` (after a writer `SELECT` that reads the options), before the
  answer is verified, so of two answers only one uses it and a failed answer burns it. A challenge lives
  `challenge_ttl_seconds` (30 to 600, 300 by default), which is also the options' `timeout`.
- Registration asks for a discoverable credential (`residentKey: required`), `attestation: none`, and ES256, EdDSA
  (when sodium is loaded) and RS256, excluding the identity's passkeys. The statement formats webauthn-lib checks
  without further dependencies are accepted for their internal consistency (`none`, `packed`, `fido-u2f`,
  `android-key`, `tpm`, `apple`), since under `none` a browser may pass an authenticator's statement through; no trust
  path or metadata is evaluated and every passkey is recorded as unattested.
- An identity's passkeys for a relying party share one user handle: 32 random bytes the first one was registered under,
  read back (on the writer) when the options of every later registration are handed out. It carries no personal data
  and does not depend on `app.key`. Registrations whose options were handed out before the first completed (on two
  devices or in two tabs) may store two handles; each passkey is checked against its own.
- A registration and an assertion must come from one of the relying party's origins, unframed: client data with
  `crossOrigin: true` is refused by `WebAuthn` itself, with or without `topOrigin`, since webauthn-lib's
  `CheckTopOrigin` only acts when the browser names a `topOrigin`, which WebAuthn Level 2 browsers do not.
- An assertion must come from one of the relying party's origins, unframed, with the relying party id's hash, user
  presence and verification, a valid signature over the challenge, and the passkey's own user handle (usernameless, the
  answer must carry it; for a factor the identity is known, so the passkey's handle is the one checked).
- The sign counter rule (`Passkeys\SignCounter`), with `s` stored and `p` presented: `s = 0` and `p = 0` accepted, the
  count stays 0; `p > s` accepted, the count set to `p` by `UPDATE ... WHERE id = ? AND sign_count = s`, so of two
  assertions read against one count only one moves it; anything else refused as `passkey_counter_regressed`, with
  nothing written, so a clone cannot lock the genuine authenticator out. webauthn-lib's own counter check is replaced by
  `DeferredCounterCheck`, which accepts everything. On MySQL an update that matches but changes nothing reports no row,
  so a `0`/`0` use whose update reports none is accepted when the writer still holds the passkey at 0: it has no count
  to race for, but a passkey removed while its sign-in was in flight is refused as a lost race is, so no session starts
  after the removal (and after `RevokeDevicesOnPasskeyRemoval`) committed.
- Every read that decides a ceremony (challenge, passkey, the identity's passkeys and handle) is on the write
  connection; every write is one conditional statement (registration an `insertOrIgnore` on the digest, so a duplicate
  is `already_registered` without a caught violation).
- The owner columns are matched in the statement and then compared exactly (`PasskeyOwner::owns()` and the relying party
  id for a passkey found, listed or removed; for a challenge used up, its recorded ceremony, guard and relying party as
  well as the type and key), since a column's collation, such as MySQL's default `_ci`, can count distinct values like
  `alice` and `Alice`, or guards `api` and `API`, as equal.
- Events report writes once committed on the passkey's connection (`AfterCommit`): `PasskeyAdded`, `PasskeyUsed`,
  `PasskeyRemoved`, each a `ContextEvent` with the guard, the client, the owner, the method `passkey` and the passkey's
  id in `credentialId`. No event, summary or exception carries a credential id, public key, user handle or count.

## Success Path

- Registration: `registrationOptions($identity, $userName, $displayName)` writes a `register` challenge;
  `register($identity, $challenge, $credential, $name)` uses it up, parses the browser's `PublicKeyCredential` (JSON or
  decoded), runs webauthn-lib's attestation ceremony against the stored options and the relying party, inserts the
  passkey (name cleaned and cut to 255 characters, only WebAuthn's own transports kept) and answers
  `PasskeyRegistration::registered()` with its `PasskeySummary`; `PasskeyAdded` once committed.
- Sign-in: `signInOptions()` reserves a slot on the client's IP address under the guard's `passkey_options` limit
  (never given back; its `per_identifier` must be `null`, as there is no identifier, and `AttemptLimits` refuses any
  other value) and writes a `sign_in` challenge naming no credential. `Auth::sessions()->signIn('passkey',
  ['challenge' => ..., 'credential' => ...])` runs the session service as for any method: no identifier, so the
  `sign_in` limit counts only the IP address; inside the credential timebox `PasskeySignIn` uses the challenge up,
  finds the passkey, loads its owner through the guard's provider (`retrieveById`, the very model recorded), takes a
  slot on the owner's account limit, verifies the assertion and applies the counter rule; `PasskeyUsed` once the use is
  committed, whether or not the session service then admits the owner. The device records the method `passkey` and no
  identifier type.
- Factor (the seam for a further-factor package): `factorOptions($identity)` writes a `factor` challenge allowing only
  the identity's passkeys; `verifyFactor($identity, $challenge, $credential)` applies the same checks for that identity
  and answers `PasskeyFactorResult::verified()` with the passkey's summary as its use left it, with `PasskeyUsed`. It
  counts nothing and reports no failure: the factor's outcome is the further-factor package's.
- Management: `passkeys($identity)` lists summaries oldest first; `remove($identity, $id)` deletes the identity's
  passkey of the relying party with one conditional `DELETE` and reports `PasskeyRemoved` from the call that removed it.
  The optional `Listeners\RevokeDevicesOnPasskeyRemoval` then ends the identity's sessions (`factor_removed`).

## Failure / Edge Cases

- Registration answers a `PasskeyRegistration` whose status (`PasskeyRegistrationStatus`) is `challenge_invalid`
  (unknown, malformed, expired, used, or another guard's, relying party's, purpose's or identity's challenge),
  `response_invalid` (malformed or not verified, an assertion included) or `already_registered` (the digest exists, for
  anyone), with no passkey.
- A factor is refused with `PasskeyFactorResult::failed()` and its reason, unconcealed: `passkey_challenge_invalid`,
  `invalid_credentials` (malformed, not verified, or not the identity's passkey) or `passkey_counter_regressed`.
- A sign-in fails as `passkey_challenge_invalid` when its challenge cannot be used, in the result too (it reveals no
  account; the client starts again), and otherwise as `invalid_credentials`: a malformed answer, a passkey of no or
  another relying party, an owner the provider does not return as recorded, an account with no attempts left (the event
  says `account_rate_limited`, and the assertion is not checked), or an assertion that does not verify. A regressed
  counter is `passkey_counter_regressed` on the event and `invalid_credentials` in the result (a concealed reason, see
  `FailureReason::isConcealed()`).
- Enumeration: sign-in names no identifier, and every refusal that could tell one passkey or account from another (the
  `invalid_credentials` cases above and a regressed counter) gives the same result and takes the whole credential
  timebox, whether or not an owner was looked up; `signInOptions()` does no identity work. The one-time codes, API keys
  and client credentials are held to the same criterion (`one-time-codes.md`, `machine-credentials.md`).
- `signInOptions()` past its limit throws `ThrottleRequestsException` (429, `Retry-After`) and writes nothing.
- webauthn-lib reports malformed input and failed checks by throwing exceptions of every kind, and PHP warnings on
  input of the wrong shape, which Laravel's error handler raises as exceptions; `WebAuthn::refusing()` turns any of them
  into a refusal. Its steps read only the answer, the options and the stored credential, so nothing else is hidden; a
  database error elsewhere propagates as a server error.
- A rolled-back caller transaction on the passkey's connection rolls back the challenge's use, the passkey's insert or
  update, and their events.

## Implementation Anchors

- `src/Passkeys/PasskeyService.php`, `src/Passkeys/PasskeySignIn.php`, `src/Passkeys/PasskeyAssertions.php`.
- `src/Passkeys/PasskeyRegistration.php`, `src/Passkeys/Enums/PasskeyRegistrationStatus.php`,
  `src/Passkeys/PasskeyFactorResult.php` (see `outcomes.md`).
- `src/Passkeys/WebAuthn.php` (webauthn-lib: options, parsing, ceremonies), `src/Passkeys/DeferredCounterCheck.php`,
  `src/Passkeys/SignCounter.php`.
- `src/Passkeys/PasskeyChallenges.php`, `src/Passkeys/PasskeyCredentials.php`, `src/Passkeys/PasskeyOwner.php`,
  `src/Passkeys/RelyingParty.php`.
- `src/Models/Passkey.php`, `src/Models/PasskeyChallenge.php`,
  `database/migrations/2026_04_06_000004_create_passkeys_table.php`,
  `database/migrations/2026_04_06_000005_create_passkey_challenges_table.php`.
- `src/Events/PasskeyAdded.php`, `src/Events/PasskeyUsed.php`, `src/Events/PasskeyRemoved.php`,
  `src/Listeners/RevokeDevicesOnPasskeyRemoval.php`.

## Authoritative Tests

- `tests/Feature/Passkeys/PasskeyServiceTest.php`, `tests/Feature/Passkeys/PasskeySignInTest.php`,
  `tests/Feature/Passkeys/PasskeyAssertionsTest.php`, `tests/Feature/Passkeys/PasskeyRoutesTest.php` (over HTTP).
- `tests/Feature/Passkeys/WebAuthnTest.php`, `tests/Unit/Passkeys/RelyingPartyTest.php`,
  `tests/Unit/Passkeys/SignCounterTest.php`, with the software authenticator
  `tests/Fixtures/Passkeys/VirtualAuthenticator.php`.
- `tests/Unit/Passkeys/PasskeyRegistrationTest.php`, `tests/Unit/Passkeys/PasskeyFactorResultTest.php`,
  `tests/Integration/Passkeys/PasskeyOutcomesTest.php` (what each outcome wrote).
- `tests/Integration/Passkeys/ConcurrentPasskeyTest.php` (races on PostgreSQL and MySQL),
  `tests/Integration/Passkeys/ReplicaPasskeysTest.php`, `tests/Integration/Migration/PasskeyTablesSchemaTest.php`.
- `tests/Performance/PasskeyQueryBudgetTest.php` (query budgets and the timebox),
  `tests/Performance/PasskeyEnumerationTest.php` (the enumeration criterion against a slow identity store).
- `tests/Feature/Sessions/MachineIdentitySignInTest.php` (`testAPasskeyWhoseOwnerBecameAMachineIsRefused`).

## Change Triggers

- A new ceremony, purpose or column; a change to the counter rule or to what an assertion must prove.
- Accepting attestation (trust paths or metadata), or offering another algorithm.
- A webauthn-lib major version, or a change to how it reports refusals.
