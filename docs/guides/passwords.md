# Passwords

`Auth::passwords($guard)` is the password service of a `jwt` guard (an `InvalidArgumentException` names any other):
the password policy, and the one call a registration, a change or a reset makes to set a password. Routes, forms and
messages stay yours.

## Password policy

```php
'passwords' => [
    'min_length' => 15,
    'max_length' => 128,
    'letters'    => false,
    'mixed_case' => false,
    'numbers'    => false,
    'symbols'    => false,
    'breached'   => ['when_unavailable' => 'reject'],
    'reset'      => ['link_ttl_seconds' => 3600],
],
```

A new password has at least `min_length` characters (8 to 128) and at most `max_length` (`min_length` to 4096), counted
as Laravel's `min` and `max` rules count them (`mb_strlen`). The default minimum of 15 is NIST SP 800-63B's for a
password used as the only factor; if every sign-in also requires a further factor (see
[Additional factors](signing-in.md#additional-factors)), you may lower it to 8. While Laravel's hashing driver is bcrypt
(its default), which reads only the first 72 bytes and ignores the rest, a password of more than 72 bytes is refused as
too long, and `min_length` may be at most 72; bcrypt also cannot hash a null character, so a password holding one is
refused as `null_character` rather than failing in the hasher. `letters`, `mixed_case`, `numbers` and `symbols` turn on
the composition rules of Laravel's `Password` rule, with its exact expressions; they are off by default, as NIST advises
against them. Each value fails closed with an `InvalidArgumentException` naming the key when a password is first
checked, and `authentication:check` reports it under `[passwords]`.

A password that passes those rules is then given to the bound `BreachedPasswordChecker`, which says whether it is known
from a breach. The package ships no breach service: the default checker, `NoBreachedPasswordCheck`, finds nothing, so
it protects nothing, and NIST expects a check against a blocklist of breached and common passwords. Bind your own:

```php
use App\Auth\BreachRangeChecker;
use SineMacula\Laravel\Authentication\Contracts\BreachedPasswordChecker;

$this->app->singleton(BreachedPasswordChecker::class, BreachRangeChecker::class);
```

```php
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Facades\Http;
use SineMacula\Laravel\Authentication\Contracts\BreachedPasswordChecker;
use SineMacula\Laravel\Authentication\Exceptions\BreachedPasswordCheckUnavailableException;

// Asks a breach corpus that answers by hash prefix, so the password never leaves the server.
final class BreachRangeChecker implements BreachedPasswordChecker
{
    public function isBreached(#[\SensitiveParameter] string $password): bool
    {
        $hash = strtoupper(sha1($password));

        try {
            $response = Http::timeout(2)->get(config('services.breaches.url') . '/range/' . substr($hash, 0, 5))->throw();
        } catch (ConnectionException|RequestException) {
            throw new BreachedPasswordCheckUnavailableException('The breached-password service did not answer.');
        }

        return str_contains($response->body(), substr($hash, 5) . ':');
    }
}
```

When the checker cannot answer, it throws `BreachedPasswordCheckUnavailableException` (never with the password in the
message): the exception is reported to your exception handler, and `breached.when_unavailable` decides what happens to
the password. Laravel's own breached check, `Password::uncompromised()` over its `UncompromisedVerifier`, is not the
seam: its verifier reports an outage and answers "not breached", so it always fails open and `when_unavailable` could
not hold. `reject` (the default) refuses it as `breach_check_unavailable`, failing closed, so an outage blocks new
passwords rather than letting a breached one through; `allow` lets it through, failing open. Any other exception the
checker throws propagates.

`check($password)` gives the policy's verdict, a `PasswordCheck` whose `violations` list every rule the password breaks
(`passes()` when there is none), as `PasswordViolation` cases: `too_short`, `too_long`, `null_character`, `letters`,
`mixed_case`,
`numbers`, `symbols`, and, only once the others pass, `breached` or `breach_check_unavailable`. `rule()` returns
Laravel's `Password` rule with the same length and composition, for a form request's validation:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;

$request->validate(['password' => ['required', 'confirmed', Auth::passwords('api')->rule()]]);
```

The rule runs no breached check (it does not add `uncompromised()`) and cannot see bcrypt's byte limit or its null
character, so `set()` (or
`check()`) has the last word. It is built from the package's settings, not from `Password::defaults()`: a form that
validates with your own defaults is checked against those, and `set()` still applies the package's policy. The
policy applies only to passwords being set: the automatic rehash of an outdated hash on sign-in re-encodes the password
the identity already has, so an older password shorter than today's minimum still signs in, and is rehashed.

## Setting a password

`set($identity, $password, $flow, ?Device $except = null, ?ClientContext $client = null)` applies the policy, and only
a password that passes is hashed with Laravel's `Hasher` and stored; a password that fails writes nothing and reports
nothing. The result is a `PasswordResult`: `set` (or `isSet()`), the `violations` when it was not, and how many devices
the flow `revoked`. The events report `$client`, or the client of the request the guard is serving, so pass one when
you set a password from a queued job or a console command. The `PasswordFlow` decides what else happens, in one
transaction on the identity's connection:

| Flow           | For                                                       | Ends                                                |
|----------------|-----------------------------------------------------------|-----------------------------------------------------|
| `REGISTRATION` | The first password of an identity your registration makes | No session                                          |
| `CHANGE`       | A signed-in identity replacing its own password           | Every session but `$except`, as `passwordChanged()` |
| `RESET`        | A password set without the old one, after a proof         | Every session, as `passwordReset()`                 |

```php
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;

Route::middleware('auth:api')->put('/password', function (Request $request, AttemptLimiter $limiter) {
    $passwords = Auth::passwords('api');
    $identity  = Auth::identity();

    $request->validate(['current_password' => 'required', 'password' => ['required', 'confirmed', $passwords->rule()]]);

    $slot = $limiter->acquire(new AttemptSubject('api', AttemptFlow::SIGN_IN, $identity->email, 'email', $request->ip()));

    if (!$slot->granted()) {
        return response()->json(['message' => 'Too many attempts.'], 429)->header('Retry-After', (string) $slot->retryAfter);
    }

    $result = $identity->getConnection()->transaction(function () use ($passwords, $identity, $request) {
        $locked = $identity->newQuery()->lockForUpdate()->find($identity->getKey());
        $right  = $locked !== null && Auth::guard('api')->getProvider()->validateCredentials($locked, ['password' => $request->input('current_password')]);

        return $right ? $passwords->set($locked, $request->input('password'), PasswordFlow::CHANGE, Auth::device()) : null;
    });

    if ($result === null) {
        return response()->json(['message' => 'The current password is wrong.'], 422);
    }

    $limiter->release($slot);

    return $result->isSet()
        ? response()->noContent()
        : response()->json(['violations' => array_map(fn ($violation) => $violation->value, $result->violations)], 422);
});
```

`set()` is a trusted call, as `login()` is: you decide that the identity may have the password, and you choose the flow
on the server, never from input, because a registration ends no session. Ask for a recent reauthentication before a
change, as above, so a stolen session cannot change the password and keep itself signed in. Checking the current
password with the provider's `validateCredentials()` counts no attempt, so the route takes a slot of the guard's
`sign_in` limits from the bound `AttemptLimiter` first, as a sign-in's password does, counted in the database for the
identifier and the IP address, and gives it back once the password is right. The transaction locks the identity's row
before the current password is checked and holds it through `set()`, so a reset racing the change comes either before
the check, which then fails against the reset's password, or after the change, whose new password outdates the reset's
link or code. Without the lock, a request that checked the old password before a reset could set its own after it. The
current password is checked against the row the transaction locked, not against an identity looked up by its address: by
then another identity may hold the address the session was opened with. Take and give back the slot outside the
transaction: inside it, the counters' rows would stay locked until the commit, and on MySQL two transactions that each
create a counter in the same gap of the index deadlock. A change ends every session of the identity, through every
guard, but the device in `$except` (the request's own device, to keep it signed in; `null` ends them all); a reset ends
every session. Both move the identity's "tokens valid after" cutoff when it keeps one and end its pending sign-ins (see
[Revoking on security changes](sessions.md#revoking-on-security-changes)), and report each revoked device with
`DeviceRevoked` and then `SignedOutEverywhere`. `$except` is for a change only. Whatever the flow, the same transaction
invalidates every password reset link and code still waiting for the identity's identifiers, through every guard whose
provider returns the identity (a provider whose configuration names no model, a custom `Auth::provider()` driver, is
assumed to; see [Password reset](#password-reset)): a link or code someone else obtained before cannot take the account
back once its owner has set a new password. A change or a reset also invalidates the sign-in codes waiting for those
identifiers, which would open a session after the ones it ended, and cancels every identifier change the identity has
pending (see [Changing identifiers](identifier-changes.md)); a registration ends no session and leaves them. The
identifiers are those its row holds, read again inside the transaction, so a model you loaded with only some columns, or
before its identifier changed, outdates them all. A guard whose provider's configured model reads another table binds
its links and codes to the identities there, so they are left alone.

A stored identity gets one query-builder update of its password column (and `updated_at` when the model keeps
timestamps) on its own row, without its scopes: nothing else you changed on the model is saved or discarded, and no
model event fires, so an observer neither cancels the write nor revokes again behind it (`RevokeDevicesOnPasswordChange`
does not undo the device a change kept). The model then holds the new hash. The hash is bound into that update as any
Eloquent write binds it: every query listener sees it, and a failed update's `QueryException` carries it in
`getBindings()` and in the SQL its message quotes, unless the connection sets `mask_bindings_in_exception_messages` (an
option of recent Laravel versions). That option masks only the SQL: the driver's own message, which PostgreSQL's
`DETAIL` can fill with the failing row, is kept. Keep query logs and error reports as you keep the hashes themselves.
Only a registration may set the password of an identity not stored yet, which is then inserted with `save()`; a model
event that cancels that save throws a `LogicException`. A registration sets only a first password: given a stored
identity, it updates the row only while its password column is `null` or empty, in the same statement, and throws a
`LogicException` otherwise, since replacing a password without ending any session would be a change that leaves a stolen
session signed in. So does a change or a reset of an identity not stored, or one whose row is gone, and an identity that
is not an Eloquent model; a non-human identity (`MachineIdentity`) has no password and throws an
`InvalidArgumentException`.

`PasswordSet` reports the password set, with the flow, once the transaction commits on the identity's connection, and
never for one rolled back; its context names the guard, the client and the identity, and, for a change, the device kept.
Called inside a transaction of yours, the hash, the cutoff and the revocations are part of it, and every event waits for
its commit. When the device model lives on another connection than the identity, the devices are revoked in their own
transaction, which commits inside the identity's: a failure after it leaves the devices revoked and the password
unchanged, so more is ended, never less, and calling again finishes the job. The automatic rehash on sign-in never
fires `PasswordSet`.

## Password reset

A reset proves control of an identifier with a link's token or a one-time code, then sets the new password and ends
every session of the identity, through every guard, in one transaction. The application owns the routes, the forms and
the messages:

```php
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Codes\Enums\CodeRequestStatus;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passwords\Enums\ResetStatus;

Route::post('/password/forgot', function (Request $request) {
    $answer = Auth::passwords('api')->sendResetLink($request->only('email'));

    return $answer->status === CodeRequestStatus::RATE_LIMITED
        ? response()->json(['message' => 'Too many requests.'], 429)->header('Retry-After', (string) $answer->retryAfter)
        : response()->json(['message' => 'If the address is registered, a link is on its way.'], 202);
});

Route::post('/password/reset', function (Request $request) {
    $result = Auth::passwords('api')->reset($request->only('email', 'token', 'password'));

    return match ($result->status) {
        ResetStatus::RESET             => response()->noContent(),
        ResetStatus::PASSWORD_REJECTED => response()->json(['violations' => array_map(fn ($v) => $v->value, $result->violations)], 422),
        ResetStatus::RATE_LIMITED      => response()->json(['message' => 'Too many attempts.'], 429)->header('Retry-After', (string) $result->retryAfter),
        ResetStatus::INVALID           => response()->json(['message' => 'The link is invalid or has expired.'], 422),
    };
});
```

`sendResetLink($input, ?ClientContext $client = null)` sends a link to the identifier the input names under the guard's
password identifier (`email` unless the guard sets another, see [Sign-in](configuration.md#sign-in));
`sendResetCode($type, $input)` sends a code to the identifier the input names under `$type` (`phone`, say), which must
have a registered normaliser (see [Identifiers](identity-models.md#identifiers)). Both do the same work for every
identifier, so the answer, the statements and the time are the same whether or not anyone holds it: the guard must allow
the `password` method (`method_not_allowed` otherwise), the identifier must be one its type's normaliser accepts
(`identifier_invalid`), the identifier, in normal form, and the IP address must have requests left under the
`password_reset_request` limits (`rate_limited`, counted on every request and never given back), and no link or code may
have been issued for it within the codes' `resend_cooldown_seconds` (`rate_limited` with the seconds left). Then a token
or a code is issued for the identifier, whoever holds it, and its delivery queued (see
[One-time codes](configuration.md#one-time-codes) for the delivery queue): the answer is a `CodeRequest`, `sent` with
when it expires. A link request answers with the code requests' type as well (`CodeRequest` and
`Codes\Enums\CodeRequestStatus`, as the route above imports): a reset link's token is issued and limited by the same
engine as a code, and the answer has the same four statuses. A newer link or code replaces the one before, which stops
working at once. No identity is looked up during the request. Refusals are reported by `AuthenticationFailed` with the
flow `password_reset`.

The queued job alone decides, later, who receives it: the identity the guard's provider finds by the identifier, read on
the write connection, that is not a `MachineIdentity`, is active, holds exactly that identifier (its own, in normal
form, compared byte for byte, through `HasVerifiableIdentifiers` when it implements it and otherwise the model attribute
named after the type, so an account found only by a look-alike the column's collation matches gets nothing), and, when
the guard requires verified identifiers and the identity can report them, has it verified. Anyone else, or no one, is
sent nothing, and nothing says so. The job sends nothing for a token or code that was used, replaced or has expired
since.

A link's token is 32 random bytes, base64url-encoded (43 characters), that works once for
`passwords.reset.link_ttl_seconds` (300 to 86400, an hour by default); a reset code is a one-time code of the
`authentication.codes` length, lifetime and attempts. Both live in the codes' table, stored only as a keyed hash, bound
to the guard, the identifier's type and normal form, and their purpose, so a token never checks as a code, a reset code
never signs anyone in, and neither works through another guard. Codes are delivered through your `OneTimeCodeSender`
with the purpose `CodePurpose::PASSWORD_RESET`. Links are delivered through the bound `PasswordResetLinkSender`. The
default, `NotifyingResetLinkSender`, sends Laravel's own `ResetPassword` notification through the identity's
`sendPasswordResetNotification($token)` (`CanResetPassword`), so its `createUrlUsing()` and `toMailUsing()` hooks shape
the link and the mail. That notification links with the identity's email address and no guard, so serve one reset route
per guard; it states the expiry of `auth.passwords.<broker>.expire`, so keep that in step with `link_ttl_seconds`. While
it is bound, a guard whose password identifier is not `email` is refused a link with an `InvalidArgumentException`
before anything is counted (`authentication:check` warns about it), and an identity that does not implement
`CanResetPassword` fails the delivery job with a `LogicException`. Bind your own sender to word the message, carry the
guard or reach another identifier:

```php
use SineMacula\Laravel\Authentication\Contracts\PasswordResetLinkSender;
use SineMacula\Laravel\Authentication\Passwords\PasswordResetLink;

final class ResetLinkMailer implements PasswordResetLinkSender
{
    public function send(PasswordResetLink $message): void
    {
        // $message->token() is in clear: put it only in the link, never in a log.
        $url = url("/{$message->guard}/password/reset?token={$message->token()}&{$message->type}=" . urlencode($message->identifier));

        Mail::to($message->identifier)->send(new ResetLinkMail($url, $message->expiresAt));
    }
}

$this->app->singleton(PasswordResetLinkSender::class, ResetLinkMailer::class);
```

`reset($input, ?ClientContext $client = null)` takes the identifier under the guard's password identifier, the `token`
and the new `password`; `resetWithCode($type, $input)` the identifier under `$type`, the `code` and the `password`. The
identifier as given and the IP address are counted under the `password_reset` limits before anything else, so a flood of
guesses never reaches the hasher or your breached-password checker; a reset that succeeds gives its slots back. The rest
runs inside the guard's credential timebox (see
[Credential validation timing](configuration.md#credential-validation-timing)): a missing or malformed identifier,
token, code or password is `invalid`; a password the policy rejects is `password_rejected` with its violations, and
spends nothing; then the identity is looked up and, in one transaction, the token or code is checked whatever the
identity, a code counting its attempt as a sign-in does. The transaction locks the identity's row before it touches the
proof, as a password change does, so a reset and a change of the password or of an identifier racing on one identity
wait for each other instead of failing, and decides again on the row as locked whether the identity may reset, so a
deactivation committed since the lookup counts. A refused proof is `invalid` (an expired or exhausted one included) and
its attempt stays counted; a proof accepted for no identity, or one the job would not have sent to, is `invalid` and
stays unspent; a proof accepted for an eligible identity is spent with the new password in the same transaction, set as
`set()` sets it with `PasswordFlow::RESET` (see [Setting a password](#setting-a-password)): every session of the
identity ended, its cutoff moved, its pending sign-ins and identifier changes ended, every other reset link and code and
every sign-in code for its identifiers invalidated, through every guard whose provider returns it (a provider whose
configuration names no model is assumed to), and `PasswordSet` reported once that commits. Only a reset returns before
the timebox ends. The result is a `ResetResult`: `reset` with how many devices were `revoked`, `invalid`, `rate_limited`
with `retryAfter`, or `password_rejected` with `violations`. `AuthenticationFailed` (flow `password_reset`) says why a
reset failed: `rate_limited`, `invalid_credentials`, `code_expired`, `code_exhausted`, `link_expired`,
`machine_identity`, `identity_inactive` or `identifier_unverified`; the result never does. A reset signs no one in and
verifies no identifier.

Spending the proof with the password and the revocation needs one transaction, so the identity must live on the device
model's connection (which the codes' table shares): a guard whose provider's model is on another throws a
`LogicException` naming both connections from a request for a link or code and from a reset, before anything is counted
or issued, and `authentication:check` warns about it. A provider whose configuration names no model (a custom
`Auth::provider()` driver) cannot be checked in advance: its identity is checked once a reset's proof is accepted, so
only someone holding a valid link or code ever sees the refusal, and the proof stays unspent. Of two
resets with one token or code exactly one resets; a reset that loses to a newer link or code is `invalid`; and any
failure after the proof is accepted (or a transaction of yours rolled back around the call) undoes the proof, the
password, the cutoff and the revocations together.

The package does not use Laravel's password broker, and does not dispatch Laravel's `PasswordReset` event (in Laravel
that is your controller's). The broker answers differently for an unknown address, sends inline, can spend one token
twice, reads its tokens from a replica, keys tokens by email address only and limits per address only; adapting it would
mean replacing every behaviour it has (see `docs/design/passwords.md`). If you keep Laravel's broker instead,
`RevokeDevicesOnPasswordReset` still answers its `PasswordReset`; do not combine the two flows.
