# Passwords

## Purpose

Document the password policy a new password must pass, the one helper a registration, a change and a reset set a
password through, what each flow ends, and how a password is reset by link or code: why it is not Laravel's password
broker, how a request does the same work for every identifier, and how a reset spends its proof with the new password
and the revocation. The application owns its routes, forms, messages and registration; the package owns the policy, the
hashing, the write, the proofs and the revocation that follows them.

## Laravel's password broker, assessed

The approval asks to build on Laravel's broker where it fits. Each place it could fit was assessed against what a reset
must guarantee (single-use, expiring tokens stored hashed; consumed atomically with the password and the revocation; the
same outcome, delivery and timing for an unknown identifier; per-identifier and per-IP limits counted in the database;
every read that decides a proof on the write connection):

- **The stock `PasswordBroker` with `DatabaseTokenRepository`.** `sendResetLink()` answers `INVALID_USER` for an
  unknown identifier and `RESET_THROTTLED` only for a known one, and sends the notification inline, so the answer and
  the timing say whether the identifier is held. `reset()` tells `INVALID_USER` from `INVALID_TOKEN` and runs
  `exists()`, the callback and `delete()` with no lock or conditional consume, so one token can reset twice, and nothing
  ties the token to ending the sessions. The repository reads through the connection's read PDO (a lagging replica can
  accept a used token), keys tokens by `getEmailForPasswordReset()` only (no phone, no guard), throttles per email only,
  and its cache variant keeps authentication state in a cache.
- **A custom `TokenRepositoryInterface`.** It could fix the storage (the writer, keyed hashes), but every method takes
  a `CanResetPassword` user, so issuing needs the identity first: an unknown identifier then does different work. The
  broker still answers `INVALID_USER` before the repository runs, and still runs the callback outside any transaction
  the repository could hold.
- **A `PasswordBroker` subclass or decorator.** Fixing enumeration, atomicity and the transaction means overriding
  `sendResetLink()`, `reset()` and `validateReset()`, that is every behaviour; what would be left is the contract's
  status strings. `PasswordBrokerManager` has no `extend()`, so registering it as `Password::broker()` would mean
  replacing the manager too.

Decision: the narrowest solution that meets every criterion is a flow of the package's own on the one-time code engine
it already has (keyed HMAC at rest, one live secret per binding, a conditional single-use consume, expiry, the resend
cooldown, invalidation), with no new table. Laravel's pieces are reused where they fit: the `Hasher`, the `Timebox`,
the `Password` validation rule, and the default link delivery, Laravel's `ResetPassword` notification through
`CanResetPassword::sendPasswordResetNotification($token)` with its `createUrlUsing()` and `toMailUsing()` hooks.
Laravel's `Illuminate\Auth\Events\PasswordReset` is not dispatched (in Laravel it is the application controller's event);
`RevokeDevicesOnPasswordReset` stays for applications that keep Laravel's broker.

Laravel's own breached-password seam was assessed too: `Password::uncompromised()` asks the container's
`Illuminate\Contracts\Validation\UncompromisedVerifier`, whose default `NotPwnedVerifier::search()` catches every
exception, reports it and treats an empty or unsuccessful answer as "not breached". It always fails open, so it cannot
carry `breached.when_unavailable`, and its contract has no way to say "could not answer". The package's own
`Contracts\BreachedPasswordChecker` says so with `BreachedPasswordCheckUnavailableException`. `rule()` therefore does not
add `uncompromised()`, and builds its rule from the package's settings with `Password::min()`, not from an
application's `Password::defaults()`: a form validated with the application's defaults is judged by those, and `check()`
and `set()` still apply the package's policy.

Reset requests answer with `Codes\CodeRequest` and `Codes\Enums\CodeRequestStatus`, the code requests' types, rather
than a reset type of their own: a link's token is issued, limited and cooled down by the same engine as a code, with
the same four outcomes (`sent`, `rate_limited`, `method_not_allowed`, `identifier_invalid`) and fields, and a copy would
only duplicate them.

## Invariants

- The policy applies to a password being set (`Auth::passwords($guard)->check()` and `set()`), never to the automatic
  rehash on sign-in (`PasswordSignIn::rehash()`, Laravel's guards), which re-encodes a password the identity already
  holds: those paths are not touched, and an older password shorter than the policy still signs in and is rehashed.
- Length is counted in characters as Laravel's `min` and `max` rules count them (`mb_strlen`); `min_length` is 8 to 128
  (default 15, NIST SP 800-63B's minimum for a single factor) and `max_length` `min_length` to 4096 (default 128).
- While Laravel's hashing driver is bcrypt, a password of more than 72 bytes is `too_long` (bcrypt reads only 72 and,
  with `hashing.bcrypt.limit`, `make()` would throw), and `min_length` may be at most 72.
- The composition rules (`letters`, `mixed_case`, `numbers`, `symbols`, off by default) use exactly the expressions of
  Laravel's `Password` rule, and `rule()` builds that rule from the same settings, so a form and `check()` agree on every
  password the rule can judge. The two differences are deliberate and pinned by a parity test: the rule runs no
  breached check, and cannot see bcrypt's byte ceiling.
- The breached check runs only for a password that passes the other rules. The default `BreachedPasswordChecker`,
  `NoBreachedPasswordCheck`, finds nothing. A checker that cannot answer throws
  `BreachedPasswordCheckUnavailableException`; the policy reports it to the exception handler and then rejects the
  password as `breach_check_unavailable` (`breached.when_unavailable` = `reject`, the default: fail closed) or lets it
  through (`allow`: fail open). Any other throwable propagates.
- Every setting fails closed with an `InvalidArgumentException` naming the key when a password is first checked, and
  `authentication:check` reports it under `[passwords]`.
- `set()` is a trusted call: the caller authorises the change and chooses the `PasswordFlow` on the server. A
  `MachineIdentity` never gets a password (`InvalidArgumentException`); an identity that is not an Eloquent model, a
  change or reset of an identity not stored, and a device to keep on any flow but a change are misconfigurations. A
  registration sets only a first password: on a stored identity its `UPDATE` matches the row only while the password
  column is `null` or empty, so it can never replace a password without ending the sessions a change ends.
- A password that breaks the policy writes nothing and dispatches nothing. Only a password that passes is hashed with
  the container's `Hasher`.
- The write, the cutoff and the revocation run in one transaction on the identity's connection; `PasswordSet` is
  dispatched once that commits (`Database\AfterCommit`), never for a rollback, and never by the automatic rehash.
- A new password outdates every reset link and code still waiting for the identity, whatever the flow: the same
  transaction invalidates them (`ResetProofs`), so a link or code someone else obtained earlier (a forwarded mail, a
  mailbox read while it was compromised) cannot take the account back after its owner recovers it, through any guard
  whose provider can return the identity. A guard whose provider reads another table binds its links and codes to the
  identities there, so they are kept (`JwtGuards::namesFor()`).

## Success Path

1. `settable()`: refuse a machine, a non-model, a change or reset of an unsaved model, and `$except` outside a change.
2. `PasswordPolicy::check()`: validate every setting, then length (`too_short` / `too_long`, with bcrypt's bytes),
   then the enabled composition rules, then, only when none failed, the breached check.
3. `PasswordWriter::write()`: hash outside the transaction (the costly part), then in
   `$identity->getConnection()->transaction()`:
   - a stored identity: one query-builder `UPDATE` of the password column (and `updated_at` when the model keeps
     timestamps) on its row by key without scopes, and for a registration only while the column is `null` or empty; 0
     rows is a `LogicException`. No other dirty attribute is saved or
     discarded and no model event fires, so `RevokeDevicesOnPasswordChange` neither sees the write nor undoes the device
     a change kept. The model is given the hash with `forceFill()` and `syncOriginalAttributes()`.
   - an unsaved identity (registration only): `forceFill()->save()`; a save a model event cancels is a `LogicException`.
   - `ResetProofs::invalidate()`: one `DELETE` on the codes' table of the reset link and code bindings of every `jwt`
     guard whose provider can return the identity (its configured model reads the identity's table on the identity's
     connection, or it names no model) for each identifier the identity holds, in canonical form, of a type a reset can
     be bound to (each guard's password identifier, for links, and every type with a registered normaliser, for codes).
     An identifier is read as `ResetRecipient` reads it (through `HasVerifiableIdentifiers`, else the attribute named
     after the type, skipped when the model has none); a type the identity's verification throws a `LogicException` for
     has nothing to invalidate, since a reset of it would fail the same way, but an `InvalidArgumentException` (a
     normaliser that cannot be built) fails the write closed.
   - `CHANGE`: `SessionService::passwordChanged($identity, $except)`; `RESET`: `passwordReset($identity)` (every guard's
     devices, the identity's "tokens valid after" cutoff moved, pending sign-ins ended, their events after their
     commit); `REGISTRATION`: nothing.
   - `PasswordSet($context, $flow)` queued on the identity connection's commit; the context names the guard, the client,
     the identity and, for a change, the device kept.
4. `PasswordResult::set($revoked)`.

## Reset requests (`sendResetLink()`, `sendResetCode()`)

1. The type: a link's is the guard's password identifier (`PasswordSignIn::identifierType()`); a code's is given and
   must have a registered normaliser (`InvalidArgumentException`), and a code needs a `OneTimeCodeSender` bound
   (`LogicException`). With `NotifyingResetLinkSender` bound, a link for a type other than `email` is an
   `InvalidArgumentException`. The code settings, the code key, the delivery queue and the
   link lifetime fail closed, and the provider's configured model must be on the device model's connection
   (`SharedConnection::assertForGuard()`, a `LogicException`), since a reset could never spend what the request issues.
   Nothing is counted yet.
2. The audience must allow `password` (`method_not_allowed`); the identifier must canonicalise to a non-empty string
   (`identifier_invalid`, reported as `invalid_credentials`).
3. `AttemptLimiter::acquire()` on `password_reset_request` for the identifier in normal form and the IP address, never
   released (`rate_limited`).
4. Issue for the binding (`CodeBinding::passwordResetLink()` / `passwordReset()`, no identity): a token
   (`OneTimeCodes::issueToken()`: 32 random bytes, base64url, 43 characters, stored as its keyed hash, lifetime
   `passwords.reset.link_ttl_seconds`) or a code (`issue()`). Within the resend cooldown: `rate_limited`.
5. `QueuedDelivery::dispatch(new SendPasswordReset($binding, $issued), new OneTimeCode)`; the answer is
   `CodeRequest::sent($expiresAt)`. No identity is looked up, so the statements and the time are the same for any
   identifier.

`SendPasswordReset` (encrypted, queued) returns unless the issuance is still current, then finds the recipient through
`ResetRecipient`: the identity the guard's provider returns (on the writer) that is an Eloquent model, not a
`MachineIdentity`, holds exactly the bound identifier (canonical, `hash_equals`; through `HasVerifiableIdentifiers` when
implemented, else the attribute named by the type), is active, and passes the audience policy's `admitIdentifier()`
when it can report verification. A link goes to `PasswordResetLinkSender`, a code to `OneTimeCodeSender` with the purpose
`password_reset`; anyone else gets nothing.

## Reset submissions (`reset()`, `resetWithCode()`)

1. Settings fail closed, and the provider's configured model must be on the device model's connection
   (`SharedConnection`, the rule identifier changes share; `LogicException` naming both) before anything is counted.
2. `acquire()` on `password_reset` for the identifier as given and the IP address (`rate_limited`), before any other
   work, released only by a reset that succeeds.
3. Inside `JwtGuard::timeboxed()`: a missing or malformed identifier, token, code or password is `invalid`
   (`invalid_credentials`); the policy (`PasswordPolicy::check()`, the breached check included) rejects as
   `password_rejected`, spending nothing and reporting nothing; `ResetRecipient::find()` looks the identity up.
4. One transaction on the codes' connection (the identity's, by the rule): the proof is checked whatever the identity
   (`checkToken()`: no attempt counted, conditional consume; `check()`: attempt counted, conditional consume). Refused:
   commit (the attempt stays counted), `invalid` (`invalid_credentials`, `code_expired`, `code_exhausted` or
   `link_expired`). Accepted for no eligible identity: roll back (the proof stays unspent), `invalid` (the recipient's
   reason). Accepted for a found model on another connection than the devices (a provider whose configuration names no
   model, which step 1 cannot check): roll back and throw the connection rule's `LogicException`, only now, so the
   refusal never tells someone without a valid proof that the identifier is held. Accepted for an eligible one:
   `PasswordWriter::write($identity, $password, RESET)` (a savepoint inside), then commit; the timebox ends early and the
   reservation is released.
5. The reset signs no one in and verifies no identifier.

## Failure / Edge Cases

- Policy failure: `PasswordResult::rejected($violations)`; nothing counted, written or dispatched.
- Breached service down: reported once per check; `reject` gives `breach_check_unavailable`, `allow` passes.
- Row deleted between load and write: the `UPDATE` matches nothing, the `LogicException` rolls the transaction back, and
  no device is revoked.
- Caller transaction rolled back: the hash, the cutoff and the revocations roll back with it and no event is dispatched.
- Devices on another connection than the identity: the bulk revocation commits on the device connection inside the
  identity's transaction; a failure after it (a throwing `DeviceRevoked` listener, say) rolls the password and the
  cutoff back but leaves the devices revoked. More is ended, never less, and calling again finishes the job.
- Laravel's `Password` rule in a form accepts a breached password and a bcrypt password over 72 bytes; `set()` refuses
  both.
- Two resets with one token or code: the conditional consume lets exactly one reset; the other is `invalid`.
- A new request between a reset's read and its consume: the new issuance replaced the row, so the consume matches
  nothing and the reset is `invalid`.
- A failure after the proof is accepted (a revocation statement failing, say) or a caller's rollback: one transaction,
  so the proof, the password, the cutoff and the devices roll back together, and no event is dispatched.
- An identity on another connection than the devices: refused with a `LogicException`, since the proof and the change
  could not commit as one; `authentication:check` warns about such a guard, as it does about a non-`email` password
  identifier while Laravel's notification is the sender.

## Implementation Anchors

- `src/Passwords/PasswordService.php`
- `src/Passwords/PasswordPolicy.php`
- `src/Passwords/PasswordSettings.php`
- `src/Passwords/PasswordWriter.php`, `src/Passwords/ResetProofs.php`, `src/Guards/JwtGuards.php`
- `src/Passwords/NoBreachedPasswordCheck.php`
- `src/Contracts/BreachedPasswordChecker.php`
- `src/Exceptions/BreachedPasswordCheckUnavailableException.php`
- `src/Events/PasswordSet.php`
- `src/Testing/FakeBreachedPasswordChecker.php`
- `src/Passwords/ResetRequests.php`, `src/Passwords/ResetSubmissions.php`, `src/Passwords/ResetRecipient.php`,
  `src/Passwords/ResetInput.php`, `src/Passwords/SendPasswordReset.php`
- `src/Passwords/PasswordResetLink.php`, `src/Passwords/ResetResult.php`, `src/Passwords/Enums/ResetStatus.php`
- `src/Contracts/PasswordResetLinkSender.php`, `src/Passwords/NotifyingResetLinkSender.php`,
  `src/Testing/FakePasswordResetLinkSender.php`
- `src/Codes/OneTimeCodes.php` (`issueToken()`, `checkToken()`, `isWellFormedToken()`)
- `src/Database/SharedConnection.php`, `src/Console/PasswordChecks.php`

## Authoritative Tests

- `tests/Unit/Passwords/PasswordSettingsTest.php`
- `tests/Unit/Passwords/PasswordPolicyTest.php`
- `tests/Unit/Passwords/PasswordResultTest.php`
- `tests/Unit/Testing/FakeBreachedPasswordCheckerTest.php`
- `tests/Feature/Passwords/PasswordServiceTest.php`
- `tests/Integration/Passwords/PasswordWriterTest.php`
- `tests/Integration/Passwords/SeparateConnectionPasswordWriterTest.php`
- `tests/Performance/PasswordSetQueryBudgetTest.php`
- `tests/Feature/Passwords/ResetRequestsTest.php`, `ResetSubmissionsTest.php`, `ResetRecipientTest.php`,
  `ResetProofsTest.php`, `NotifyingResetLinkSenderTest.php`, `SendPasswordResetTest.php`
- `tests/Integration/Passwords/ReplicaPasswordResetsTest.php` (a link delivered and spent behind a lagging replica),
  `tests/Integration/Passwords/ConcurrentResetSubmissionsTest.php`,
  `tests/Integration/Passwords/SeparateConnectionResetSubmissionsTest.php`,
  `tests/Feature/Database/SharedConnectionTest.php`
- `tests/Integration/Codes/OneTimeCodesTest.php` (the token tests), `tests/Unit/Guards/JwtGuardsTest.php`
- `tests/Performance/PasswordResetEnumerationTest.php`, `tests/Performance/PasswordResetQueryBudgetTest.php`

## Change Triggers

Update this note when the policy gains or loses a rule, Laravel's `Password` rule changes its expressions, the bcrypt
ceiling or the default minimum changes, the breached check's outage behaviour changes, a flow ends different sessions,
`set()` writes more than the password column or outdates a different set of proofs, a reset request starts doing
identity-dependent work, a reset stops spending its proof in the transaction of the change, or Laravel's broker changes
in a way that would let it meet the criteria above.
