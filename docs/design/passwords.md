# Passwords

## Purpose

Document the password policy a new password must pass, the one helper a registration, a change and a reset set a
password through, and what each flow ends. The application owns its routes, forms, messages and registration; the
package owns the policy, the hashing, the write and the revocation that follows it.

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
  change or reset of an identity not stored, and a device to keep on any flow but a change are misconfigurations.
- A password that breaks the policy writes nothing and dispatches nothing. Only a password that passes is hashed with
  the container's `Hasher`.
- The write, the cutoff and the revocation run in one transaction on the identity's connection; `PasswordSet` is
  dispatched once that commits (`Database\AfterCommit`), never for a rollback, and never by the automatic rehash.

## Success Path

1. `settable()`: refuse a machine, a non-model, a change or reset of an unsaved model, and `$except` outside a change.
2. `PasswordPolicy::check()`: validate every setting, then length (`too_short` / `too_long`, with bcrypt's bytes),
   then the enabled composition rules, then, only when none failed, the breached check.
3. `PasswordWriter::write()`: hash outside the transaction (the costly part), then in
   `$identity->getConnection()->transaction()`:
   - a stored identity: one query-builder `UPDATE` of the password column (and `updated_at` when the model keeps
     timestamps) on its row by key without scopes; 0 rows is a `LogicException`. No other dirty attribute is saved or
     discarded and no model event fires, so `RevokeDevicesOnPasswordChange` neither sees the write nor undoes the device
     a change kept. The model is given the hash with `forceFill()` and `syncOriginalAttributes()`.
   - an unsaved identity (registration only): `forceFill()->save()`; a save a model event cancels is a `LogicException`.
   - `CHANGE`: `SessionService::passwordChanged($identity, $except)`; `RESET`: `passwordReset($identity)` (every guard's
     devices, the identity's "tokens valid after" cutoff moved, pending sign-ins ended, their events after their
     commit); `REGISTRATION`: nothing.
   - `PasswordSet($context, $flow)` queued on the identity connection's commit; the context names the guard, the client,
     the identity and, for a change, the device kept.
4. `PasswordResult::set($revoked)`.

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

## Implementation Anchors

- `src/Passwords/PasswordService.php`
- `src/Passwords/PasswordPolicy.php`
- `src/Passwords/PasswordSettings.php`
- `src/Passwords/PasswordWriter.php`
- `src/Passwords/NoBreachedPasswordCheck.php`
- `src/Contracts/BreachedPasswordChecker.php`
- `src/Exceptions/BreachedPasswordCheckUnavailableException.php`
- `src/Events/PasswordSet.php`
- `src/Testing/FakeBreachedPasswordChecker.php`

## Authoritative Tests

- `tests/Unit/Passwords/PasswordSettingsTest.php`
- `tests/Unit/Passwords/PasswordPolicyTest.php`
- `tests/Unit/Passwords/PasswordResultTest.php`
- `tests/Unit/Testing/FakeBreachedPasswordCheckerTest.php`
- `tests/Feature/Passwords/PasswordServiceTest.php`
- `tests/Integration/Passwords/PasswordWriterTest.php`
- `tests/Integration/Passwords/SeparateConnectionPasswordWriterTest.php`
- `tests/Performance/PasswordSetQueryBudgetTest.php`

## Change Triggers

Update this note when the policy gains or loses a rule, Laravel's `Password` rule changes its expressions, the bcrypt
ceiling or the default minimum changes, the breached check's outage behaviour changes, a flow ends different sessions,
or `set()` writes more than the password column.
