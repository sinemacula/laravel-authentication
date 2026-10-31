# Changing identifiers

`Auth::identifierChanges($guard)` changes an identity's email address or phone number once the new one is proven, and
keeps the current one until then. A change is requested, then confirmed by a one-time code sent to the new identifier or
by a signed link the application sends there; the confirmation replaces the identifier, records the new one as
verified, and tells the old one. The application owns the routes, the messages and their delivery.

The identity implements `HasChangeableIdentifiers` (it extends `HasVerifiableIdentifiers`); the
`ProvidesIdentifierChanges` trait implements it from the identifier's column and `<type>_verified_at`, and brings
`ProvidesIdentifierVerification` with it, so the model uses it in place of that trait. The application binds an
`IdentifierChangeNotifier`, which tells the old identifier: no change is requested or confirmed while none is bound. The
notice says whether the old identifier was verified when the change was requested (`previousVerified`): one never
verified, such as an address mistyped at registration, may belong to a stranger, whom a notice would tell that the
account exists and, if it named the new identifier, where its owner now is. The package queues the notice either way and
leaves that choice to the notifier; the one below sends nothing to an unverified address and names only part of the new
one.

```php
use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierChanges;
use SineMacula\Laravel\Authentication\Contracts\HasChangeableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\IdentifierChangeNotifier;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeNotice;

class User extends Model implements HasChangeableIdentifiers, Identity, Principal
{
    use ActsAsPrincipal, Authenticatable, ProvidesIdentifierChanges;
}

final class MailIdentifierChangeNotifier implements IdentifierChangeNotifier
{
    public function notify(IdentifierChangeNotice $notice): void
    {
        // Never verified, the old address may be a stranger's: tell it nothing.
        if (!$notice->previousVerified) {
            return;
        }

        // $notice->previous is the destination; name only part of the new address.
        Mail::to($notice->previous)->send(new EmailAddressChanged(Str::mask($notice->identifier, '*', 2, -6), $notice->changedAt));
    }
}

// In a service provider's register():
$this->app->singleton(IdentifierChangeNotifier::class, MailIdentifierChangeNotifier::class);
```

**Uniqueness.** Give the identifier's column a unique index on the stored, normalised value (the `NormalisedIdentifier`
cast stores it so; see [Identifiers](identity-models.md#identifiers)), and a composite one with the tenant's key for
identifiers unique per tenant. A confirmation checks first that the guard's identity provider finds no other identity
holding the new identifier, but only the index decides a race between two confirmations of one value: the one that loses
is refused as `taken`, inside a savepoint, so the change, its proof and any transaction you hold stay usable. Without
the index the check is best effort and a race can leave two identities with one identifier.

**Recent authentication.** A request carries a `Sessions\Reauthentication`, the proof that the identity authenticated
recently: within `identifier_changes.recent_authentication_seconds` (900 by default), from the second it names, and
never from the future.

- `Reauthentication::device($device)`: the session the change is made from. Read again on the write connection, it
  must be one of the identity's own live sessions of the guard (not revoked, deadlines not passed), signed in within
  the window. A refresh or a principal switch does not renew it; a fresh sign-in does.
- `Reauthentication::password($password)`: the identity's current password, checked in the guard's credential timebox
  against the identity read again through the guard's provider. It counts against the identity's account and the IP
  address under the `sign_in` limits, and a correct one is given back. A guard whose audience does not allow the
  `password` method takes no password as proof (`reauthentication_required`, nothing counted).
- `Reauthentication::confirmedAt($at)`: a further factor, or another proof your code verified, at `$at`. It is trusted,
  as `start()` is: never build it from a time the client sent.

An identity that signs in only with codes or passkeys reauthenticates by signing in again on the device it changes from.
A token with no device (in [access-only mode](installation.md#access-only-mode-no-devices-no-refresh), or any access
token without a `did`) has no session to offer, so `Auth::device()` is `null` there and the request must ask for another
proof. The first route below takes the password whenever one is sent, so a session signed in longer ago than the window
can confirm it instead of signing in again, and the device's recent sign-in otherwise.

**Requesting.** `requestByCode()` sends a code to the new identifier, delivered after commit by a queued job through
your `OneTimeCodeSender` with the purpose `change_identifier` (the message's `identifier` is the new one);
`requestByLink()` signs a link to your named route instead, which `link()` returns for you to send to the new identifier
(and only there: never return it to the client). The new identifier must be one the type's normaliser accepts and not
the current one; whether another identity holds it is not checked here, so the answer says nothing about it. Requests
are limited by `rate_limits.identifier_change`, counted on the new identifier, on the identity and on the IP address. A
request checks the proof, the new identifier and the limits first, on the identity's row read again; then, in one
transaction that locks that row (and the proving device's row, for a device proof), it checks again that the proof
stands and that the identifier is not the current one, and writes the change. A refusal there gives the
`identifier_change` slots back. So a password change or a reset racing a request proven by the old password, and a
revocation of the device that proves one, come either before the check under the lock, which then fails, or after the
change is written, which they then cancel. A `confirmedAt()` proof, and a password proof racing a revocation that leaves
the password as it is, are not serialised. The current identifier is read from the row as locked. The limits are counted
before the transaction, never inside it, so no counter's row stays locked until its commit: on MySQL, two transactions
that each create a counter in the same gap of the index deadlock (inside a transaction of yours, see the note on
transactions under [Rate limits](configuration.md#rate-limits)).

```php
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeRequestStatus;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;

Route::middleware('auth:api')->post('/email/change', function (Request $request) {
    $input  = $request->validate(['email' => ['required', 'email'], 'password' => ['nullable', 'string']]);
    $device = Auth::device();
    $proof  = match (true) {
        isset($input['password']) => Reauthentication::password($input['password']),
        $device !== null          => Reauthentication::device($device),
        default                   => null,
    };

    if ($proof === null) {
        return response()->json(['message' => 'Confirm your password.'], 403);
    }

    $result = Auth::identifierChanges('api')->requestByCode(Auth::identity(), 'email', $input['email'], $proof);

    return match ($result->status) {
        IdentifierChangeRequestStatus::SENT                      => response()->json(['expires_at' => $result->expiresAt->toIso8601String()], 202),
        IdentifierChangeRequestStatus::RATE_LIMITED              => response()->json([], 429, ['Retry-After' => $result->retryAfter]),
        IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED => response()->json(['message' => 'Confirm your password, or sign in again.'], 403),
        IdentifierChangeRequestStatus::IDENTIFIER_INVALID,
        IdentifierChangeRequestStatus::IDENTIFIER_UNCHANGED      => response()->json(['message' => 'Enter a new email address.'], 422),
    };
});

Route::middleware('auth:api')->post('/email/change/link', function (Request $request) {
    $input  = $request->validate(['email' => ['required', 'email'], 'password' => ['required', 'string']]);
    $result = Auth::identifierChanges('api')->requestByLink(Auth::identity(), 'email', $input['email'], Reauthentication::password($input['password']), 'email.change.confirm');

    if ($result->isSent()) {
        Mail::to($input['email'])->send(new ConfirmNewEmailAddress($result->link()));
    }

    return response()->json(['status' => $result->status->value], $result->isSent() ? 202 : 422);
});
```

| Status                      | When                                                                                                  |
|-----------------------------|-------------------------------------------------------------------------------------------------------|
| `sent`                      | The change waits for its proof until `expiresAt`                                                      |
| `rate_limited`              | The `identifier_change` limits, or a password proof's `sign_in` limits, are used up                   |
| `reauthentication_required` | The proof shows no recent authentication, the password is wrong, or the guard does not take passwords |
| `identifier_invalid`        | The type's normaliser rejects the new identifier                                                      |
| `identifier_unchanged`      | The new identifier, in its normal form, is the identity's current one                                 |

One change waits per identity and type, in `identifier_changes.table`: a newer request, through any guard, replaces it,
so the code and the link of an earlier one stop working at once. It waits `identifier_changes.ttl_seconds` (3600 by
default), and a change proven by code no longer than its code works (`codes.ttl_seconds`). `pending($identity, $type)`
reports the change waiting through this guard (its new identifier and times) and `cancel($identity, $type)` drops it,
locking the identity's row first, as a request and a confirmation do, so the three wait for each other. Ending the
identity's sessions in bulk drops every change it has waiting, of each type and through each guard, in the same
transaction: `signOutEverywhere()`, `revokeDevices()` and the security-change methods that end an identity's sessions
(see [Revoking on security changes](sessions.md#revoking-on-security-changes)), so also a change or a reset of the
password through `Auth::passwords()->set()`, a reset by link or code, and the listeners that call them. A link needs no
session, so one requested from a session that ended could otherwise still move the account to an address of the
requester's. Revoking one device, ending a principal's sessions and a registration keep them. Prune expired changes with
`php artisan model:prune --model="SineMacula\Laravel\Authentication\Models\IdentifierChange"`.

**Confirming.** `confirmByCode($identity, $type, $code)` takes the code; `confirmByLink($request)` takes the request to
the link's address, which needs no session (the link names the identity, signed). Each acts only on a change requested
through the same guard. Let the link's `GET` only show a confirmation, and confirm from its form: mail scanners and link
previews fetch links no one clicked, and a change confirmed by such a fetch (a mistyped address that reaches a
stranger's scanned mailbox, say) would make the stranger's address the one password resets go to. The form posts back to
the same signed address, query included, and `confirmByLink()` reads the signature from it. Neither confirms a change
for an identity that is not active (`CanBeActive`, see
[Active-state enforcement](identity-models.md#active-state-enforcement)): the link needs no session, so no guard has
checked it, and an account suspended after the request keeps its identifier. The answer is `invalid`, reported as
`identity_inactive`, before anything is counted.

```php
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome;

Route::middleware('auth:api')->post('/email/change/confirm', function (Request $request) {
    $input = $request->validate(['code' => ['required', 'string']]);

    return match (Auth::identifierChanges('api')->confirmByCode(Auth::identity(), 'email', $input['code'])) {
        IdentifierChangeOutcome::CHANGED => response()->noContent(),
        IdentifierChangeOutcome::TAKEN   => response()->json(['message' => 'That address is in use.'], 409),
        default                          => response()->json(['message' => 'That code does not work.'], 422),
    };
});

Route::get('/email/change/link/confirm', function (Request $request) {
    // A page whose form posts to $request->fullUrl(), so following the link changes nothing by itself.
    return view('email.confirm-change', ['action' => $request->fullUrl()]);
})->name('email.change.confirm');

Route::post('/email/change/link/confirm', function (Request $request) {
    return Auth::identifierChanges('api')->confirmByLink($request) === IdentifierChangeOutcome::CHANGED
        ? response()->noContent()
        : abort(403);
});
```

| Outcome     | When                                                                                                                                                                  |
|-------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `changed`   | The identifier was replaced by the new one, recorded as verified                                                                                                      |
| `invalid`   | No change of this guard waits, a newer request or another confirmation won, the proof does not match, the identifier changed meanwhile, or the identity is not active |
| `expired`   | The change, its code or its link has expired                                                                                                                          |
| `exhausted` | The code used up its attempts; request the change again                                                                                                               |
| `taken`     | Another identity holds the new identifier; the proof is not used up                                                                                                   |

A confirmation locks the identity's row, reads the change, checks the proof and makes the change in one transaction on
the identity's connection (the row lock comes first, as in a password change or reset, so they wait for each other;
whether the identity is still stored and active is read from the row as locked, not from the instance you pass), so the
identity must be stored on the storage connection, where the codes and the pending changes are kept (see
[Storage](configuration.md#storage)): as for a password reset, any other identity throws a `LogicException` naming both
connections before anything is counted, and `authentication:check` warns about its guard. A wrong code's attempt is
kept; a change refused once its proof is accepted (`taken`, an identifier changed meanwhile, a database error, or a
transaction you roll back) rolls back whole, so the proof is not spent. The same transaction invalidates, for every
`jwt` guard whose provider returns the identity (a provider whose configuration names no model, a custom
`Auth::provider()` driver, is assumed to) and for both the old identifier and the new one, the sign-in, password reset
and reset link codes waiting for it, and the identity's verification codes; a verification link for the old identifier
stops working by itself (it answers `invalid`), since it carries that identifier's digest. A guard whose provider's
configured model reads another table binds its codes to the identities there, which keep them.

Once the change commits, `IdentifierChanged` is dispatched and, when the identity had an identifier of the type, the
notice to the old one is queued on the delivery queue (`delivery.queue`). The change stands if the notice fails: the job
fails and the queue's retries apply. The new identifier was proven and the request recently authenticated, so rolling
the change back on a mail outage would block the owner while protecting nothing the proof did not. The identity's
sessions are not revoked: changing an identifier is not a security change of its own; end them with
`signOutEverywhere()` if your application wants that.

Every refusal is reported by `AuthenticationFailed` on the `identifier_change` flow, not concealed, since the caller
holds the identity: `reauthentication_required`, `rate_limited` (with `retryAfter`), `invalid_credentials`,
`identity_inactive`, `code_expired`, `link_expired`, `code_exhausted` or `identifier_taken`; a request's event carries
the new identifier as given. `IdentifierChangeRequested` (type, new identifier, expiry) and `IdentifierChanged` (type,
previous and new identifiers, time) carry the identifiers as strings, so a queued audit listener needs no query back. A
machine identity has no identifiers to change, so every method throws an `InvalidArgumentException` for one; an identity
that is not an Eloquent model implementing `HasChangeableIdentifiers`, a type with no registered normaliser, malformed
settings, an unbound notifier or a link route whose parameters or placeholders take a name the link sets (`guard`,
`identity`, `type`, `purpose`, `request`, `hash`, `expires`, `signature`) throw before anything is counted or written,
and `authentication:check` reports the settings (`[identifier_changes]`).
