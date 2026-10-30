# Switching principal and signing out

## Switching principal

An identity that may act as several principals (memberships of several tenants, say) switches the session it is signed
in with to another one, on the same device, proven by the session's refresh token:

```php
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;

$target = Membership::findOrFail($request->input('membership'));
$result = Auth::sessions('api')->switchPrincipalFromRequest($target);

abort_if($result === null, 401); // no refresh token in the request

if ($result->isFailed()) {
    // AuthenticationFailed was dispatched (flow principal_switch); $result->reason says why.
    if ($result->reason === FailureReason::RATE_LIMITED) {
        // A 429 with Retry-After, as a refused refresh answers, so clients wait.
        throw new ThrottleRequestsException('Too Many Attempts.', null, ['Retry-After' => $result->retryAfter]);
    }

    abort(401);
}

$tokens = $result->session->tokens;

return $result->source === RefreshTokenSource::COOKIE
    ? response()->json(['access_token' => $tokens->accessToken])
        ->withCookie(Auth::refreshTransport('api')->cookie($tokens->refreshToken, $result->session->device))
    : response()->json(['access_token' => $tokens->accessToken, 'refresh_token' => $tokens->refreshToken]);
```

The refresh token proves the session, never an access token: a stolen access token lives minutes and must not mint a
refresh credential. `switchPrincipalFromRequest()` reads it as `refreshFromRequest()` does, through the guard's refresh
token transport, so it comes from the one source the guard allows and a token from the refresh cookie gets the cookie's
cross-site checks; put the switch route under the cookie's path. It returns `null` when the request carries no token,
and a token the transport refuses fails with its reason (`refresh_token_conflict`, `cross_site_request`,
`token_invalid`, reported as an `AuthenticationFailed` of flow `principal_switch`) without the device being touched. The
result's `source` says where the token came from, so a switch read from the cookie answers with the new refresh token
in the cookie, as a refresh does. `switchPrincipal($refreshToken, $target)` remains for a token your code reads itself;
never pass it one read from the refresh cookie.

A switch is judged as a refresh is: counted against the same refresh limits (`rate_limited`, with the wait in the
result's `retryAfter`: unlike `refreshFromRequest()`, which throws the 429 itself, a switch returns its refusal, so
answer it with `Retry-After` as above), the token parsed for this guard, the device found, of this guard, live, and the
rotation id current, or the previous one inside the grace window; any other id is a replay and revokes the device
(`rotation_reuse`). On every path the device's owner must still be returned by the guard's provider and be active, the
target must resolve through the resolver's hinted path as the very principal named, of its class, owned by that identity
(read from the principal's own key, not trusted to the resolver), active, in an active tenant and admitted by the
audience policy, also with the type of identifier the session's sign-in used (which the device records), so a principal
your policy refuses to that identifier cannot be reached by switching to it, the session's sign-in method must still be
allowed, and the additional-factor policy must not ask for a further factor (`additional_factor_required`: sign in again
as the target).

With the current rotation id, the token's principal must be the one the device records (`device_principal_mismatch`).
The switch keeps the session's absolute deadline, held to the target type's absolute lifetime counted from the sign-in
(`session_expired` when that has passed), restarts the idle one under the target's lifetimes, issues both tokens for the
target, then records the target, the switch time (`principal_switched_at`), the rotation and both deadlines in one
compare-and-swap. The access tokens of the principal switched from stop at once, and switching back does not revive them
(see [Device](configuration.md#device)). A switch to the principal the device already records rotates the credential
like a refresh and reports no switch.

With the previous rotation id inside the grace window, the current credential for the target is handed back, writing
nothing, only when the device records the target and either its last rotation was the switch to it (a lost switch
response, retried) or the token's own principal is the target; anything else is `rotation_conflict`, without revoking,
and the client retries with its current token. When another request changes the device between the switch's read and its
write, the row is read again with a lock and judged once more under the same rules; the swap is never tried twice.

A switch binds the guard to the target (`Authenticated`, `PrincipalAssigned`, `DeviceAuthenticated`, no `Login`) and
dispatches `PrincipalSwitched` once committed on the device's connection, with the new principal and tenant in its
context, and the previous principal as the device recorded it (`previousPrincipalType`, `previousPrincipalId`) and, when
it still resolves for the identity, the principal itself (`previousPrincipal`).

## Signing out and revoking sessions

`Auth::logout()` (or `Auth::guard('api')->logout()`) signs the request's session out through the session service: the
device the guard is bound to is revoked with reason `signed_out`, `DeviceRevoked` reports it once committed, Laravel's
`Logout` follows, and the guard stays signed out for the rest of the request. The session's access and refresh tokens
stop at once. A session without a persisted device (an access-only token) has nothing to revoke and is only forgotten;
a guest request does nothing. `Auth::sessions('api')->signOut()` does the same and returns whether it revoked a device.
`logout()` cannot reach the response, so clear a browser's refresh cookie on it with
`Auth::refreshTransport('api')->forgetCookie()` (see [Refresh token cookie](refreshing.md#refresh-token-cookie)).

The session service also revokes sessions for the application's own screens and flows:

```php
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Facades\Auth;

$sessions = Auth::sessions('api');

// "Sign out of all other devices": every session of the identity, of every guard, but this one.
$sessions->signOutEverywhere(keepCurrentDevice: true);

// A device list's "sign out" button: only the identity's own device is found.
$sessions->revokeDevice(Auth::identity(), $deviceId, RevocationReason::REVOKED);

// An administrator ends every session of an identity, or every session acting as a principal.
$sessions->revokeDevices($identity, RevocationReason::REVOKED, except: null);
$sessions->revokePrincipalDevices($membership, RevocationReason::REVOKED);
```

Each device is revoked by one conditional update that only applies while it is not revoked yet, so every call is
idempotent: the first revocation's time and reason are kept, and of two calls racing for a device only the one that
revoked it reports `DeviceRevoked`. `revokeDevice()` finds the device through the owner's `devices()` relation on the
write connection, so another identity's device is simply not found and the call returns `false`, as it does for an
unknown or already revoked one. `revokeDevices()` covers every device the identity's relation returns, of every guard;
`revokePrincipalDevices()` every device of the configured model that records the principal. Both keep the `except`
device when one is given, return how many devices they revoked, and also end the scope's pending sign-ins (a further
factor or a principal choice waiting to be completed), so a credential issued before the revocation cannot start a
session after it. `revokeDevices()` also cancels the identity's pending identifier changes, of every type and through
every guard: a change link needs no session, so one requested from a session that ends could otherwise still move the
account to an identifier of the requester's (see [Changing identifiers](identifier-changes.md)). `revokeDevice()` and
`revokePrincipalDevices()` leave them, since the identity keeps its other sessions. `signOutEverywhere()` is
`revokeDevices()` for the request's identity with reason
`signed_out_everywhere`; it returns `0` on a guest request, and it leaves the guard bound for the rest of the request
(call `signOut()` as well to end the current session too). With `keepCurrentDevice: true` on a request whose session has
no device (an access-only token), the session is kept by leaving the identity's "tokens valid after" cutoff where it is,
since a device-less token can only be ended through it: every device is still revoked, but the identity's other
device-less tokens keep working too, until they expire.

A bulk revocation first moves the scope's "tokens valid after" cutoff to now, when the identity or principal records one
(`HasTokensValidAfter`), then, in one transaction on the device model's connection, revokes each unrevoked device, read
on the write connection in key order 500 at a time, and deletes the pending sign-ins and, for an identity, its pending
identifier changes. Once that transaction commits,
`DeviceRevoked` reports each device it revoked (with the device's own guard) and then `SignedOutEverywhere` reports the
scope, with the acting guard, the reason, the count (also `0`, so the action itself is recorded), the cutoff it set (or
`null`), and the device it kept. If the device transaction fails, the cutoff it already moved stands: more is cut off,
never less, and calling again finishes the job. One window stays open: a sign-in that has already passed its credential
check when a bulk revocation reads the devices can still create its device afterwards. Closing it would take a lock that
every sign-in and every revocation take on the identity, which the package does not add.

### Listing devices

`devices()` returns one page of an identity's active devices for a "where you're signed in" screen: every session it
holds on any guard that is not revoked and is before both its idle and absolute deadline, most recently used first
(devices never used last), then newest first:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;

Route::middleware('auth:api')->get('/devices', fn () => Auth::sessions('api')->devices(Auth::identity(), perPage: 20));
```

Each item is a `DeviceSummary`, safe to return as it is: the device id (its `did`), guard, sign-in method, client name
and platform, the creation time (for a model with Eloquent timestamps), IP address and user agent, when the session
started (its latest sign-in on that device), the last use and its IP address and user agent, both deadlines, and
`current`, which marks the device the request is authenticated with on that guard. It never holds a refresh digest, the
rotation time, the revocation columns, the owner or the principal, and `toArray()` and JSON use snake_case keys and
ISO-8601 times. A page holds 1 to 100 devices (15 by default; anything else is an `InvalidArgumentException`), and the
page is the request's `page` parameter unless you pass one. The list is read on the write connection through the
identity's `devices()` relation, in two queries (a count and a select), so a device revoked a moment ago is never shown.
An identity that does not implement `HasDevices`, or whose `devices()` relation queries a model that is not an
`EloquentDevice`, is a `LogicException`.

The same rule is a query scope on any model that uses `ActsAsDevice`, for your own queries:

```php
Device::query()->active()->where('guard', 'api')->count();
```

### Revoking on security changes

Call the session service from your own flows when something about an identity's security changes; each ends the
affected sessions as a bulk revocation, with its own reason, moves the scope's cutoff, and ends its pending sign-ins
and, for the four that end an identity's sessions, its pending identifier changes:

| Method                                             | Ends                                       | Reason                  |
|----------------------------------------------------|--------------------------------------------|-------------------------|
| `passwordChanged($identity, ?Device $except)`      | The identity's sessions, but `$except`     | `password_changed`      |
| `passwordReset($identity)`                         | Every session of the identity              | `password_reset`        |
| `factorRemoved($identity, ?Device $except)`        | The identity's sessions, but `$except`     | `factor_removed`        |
| `identityDeactivated($identity)`                   | Every session of the identity              | `identity_deactivated`  |
| `principalDeactivated($principal)`                 | Every session acting as the principal      | `principal_deactivated` |
| `tenantDeactivated($tenant, iterable $principals)` | Every session acting as a listed principal | `tenant_deactivated`    |

Never call `passwordChanged()` for the automatic rehash of a password on sign-in: the password did not change. These
methods end sessions, pending sign-ins and pending identifier changes only. A change or a reset set through
`Auth::passwords()->set()` (see [Setting a password](passwords.md#setting-a-password)) calls them and also ends the
other proofs that could take the account back without a session: the reset links and codes and the sign-in codes of the
identity. A registration calls none of them and ends only the reset links and codes. A password your own flow saves
another way leaves those proofs as they are. `factorRemoved()` is the seam a further-factor package calls when an
identity removes a factor. Devices record principals, not tenants, so `tenantDeactivated()` takes the tenant's
principals from you: each must act within the tenant (read on the write connection from the principal as stored, so a
`tenant` relation you loaded does not decide and Eloquent's strict mode does not stop the read), or an
`InvalidArgumentException` is thrown before anything is written. A `CanBeActive` tenant already deleted or soft-deleted
still works, since a principal whose `TenantUnavailableException` names that very tenant (its class and key, as
`ActsAsPrincipal` reports it) acts within it, so restoring the tenant later revives no session; a tenant that does not
implement `CanBeActive` reads as no tenant once it cannot be loaded, so call `tenantDeactivated()` before deleting it; a
principal listed twice counts once, and every principal's sessions end in one device transaction, with one
`SignedOutEverywhere` per principal. Deactivation already stops every token at once through the live activity checks
(see [Active-state enforcement](identity-models.md#active-state-enforcement)); revoking makes the end outlast a
reactivation and records why.

Three optional listeners call them for you. Registering one is the opt-in, and each revokes only once the change that
triggered it is committed on the changed model's connection, so a change that is rolled back revokes nothing:

```php
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authentication\Listeners\RevokeDevicesOnDeactivation;
use SineMacula\Laravel\Authentication\Listeners\RevokeDevicesOnPasswordChange;
use SineMacula\Laravel\Authentication\Listeners\RevokeDevicesOnPasswordReset;

Event::listen(PasswordReset::class, RevokeDevicesOnPasswordReset::class);
User::observe(RevokeDevicesOnPasswordChange::class);
User::observe(RevokeDevicesOnDeactivation::class);
Membership::observe(RevokeDevicesOnDeactivation::class);
```

- `RevokeDevicesOnPasswordReset` answers Laravel's `PasswordReset` (the password broker's) with `passwordReset()`.
- `RevokeDevicesOnPasswordChange` observes an identity model and answers a saved change of its password column with
  `passwordChanged()`, revoking every device, the one the change was made from included; to keep that one, call
  `passwordChanged($identity, Auth::device())` yourself instead. The automatic rehash on sign-in is not a change, and
  the observer ignores it: the package's own sign-ins run it marked, and so do Laravel's guards (`attempt()`,
  `attemptWhen()`, `once()`, as a web login over the same user model does), whose attempt the package follows through
  Laravel's auth events. A save is the rehash only when it re-encodes the password signed in with (both the hash it
  replaces and the hash it saves verify it) and no change of the user's password has run since the rehash or attempt
  began; for an attempt, it must also save the very model instance the attempt validated. So a new password saved before
  the attempt ends (by an `attemptWhen()` callback, say) revokes, and so does any later save of the user, a change back
  to that password or a fresh hash of it through another instance included. An attempt made inside another attempt's
  callback, or the session's user resolved there, leaves the outer attempt's rehash alone; two cases end the outer
  attempt early, so its rehash then revokes: an `Auth::login()` of the very instance it validated inside its callback,
  and a refused inner attempt that validated that same instance (from a provider that caches its users). Users are told
  apart by the row they are stored in (connection, database, table and key), so the same key in another tenant's
  database is another user. Confirming the current password with `validate()` before changing it is not an attempt, so
  the change that follows revokes; so does Laravel's `logoutOtherDevices()`, whose forced rehash exists to sign the
  other sessions out, even while an attempt for the user is open or the package's own rehash runs: the package holds a
  save it takes for a rehash until the request or job ends, and the `OtherDeviceLogout` event that follows a forced
  rehash runs it, so a sign-out after an attempt's rehash in the same request may revoke twice. Only changes saved
  through Eloquent fire model events.
- `RevokeDevicesOnDeactivation` observes a `CanBeActive` identity or principal model and answers an update that turns
  it from active to inactive with `identityDeactivated()` or `principalDeactivated()` (a 2D model is treated as the
  identity). It compares a copy holding the attributes from before the update with the model as it is now, so it suits
  activity held in the model's own attributes (`ProvidesActiveState`); for activity derived from anything else, call
  the method yourself. A tenant has no listener: devices record principals, not tenants, so call
  `tenantDeactivated()` with the tenant's principals. Registering the observer on a model that is neither an identity
  nor a principal throws a `LogicException` when that model is deactivated.

A password reset through Laravel's broker saves the new password through Eloquent before your code fires
`PasswordReset`, so with both password listeners registered the observer revokes every device first, as
`password_changed`, and the reset listener then finds none left to revoke (its `SignedOutEverywhere` reports
`password_reset` with a count of `0`). Register one of them for each flow: the observer alone ends sessions on every
change of password, resets included, as `password_changed`; to record resets as `password_reset`, register the reset
listener and call `passwordChanged()` from your password-change flow instead of registering the observer.

Revocation covers every guard whichever session service acts; the acting guard only names the guard and request the
events report. It is the current default guard when that is a `jwt` guard, else the first `jwt` guard in
`auth.guards`, so a change made on a route guarded by another driver (whose middleware makes that guard the default)
still revokes. To name it, bind the listener's `$guard`:

```php
$this->app->when(RevokeDevicesOnPasswordChange::class)->needs('$guard')->give('api');
```

With no `jwt` guard configured at all, a listener throws an `InvalidArgumentException`.

### Access tokens without a device

An access token issued without a device (access-only mode, see
[Access-only mode](installation.md#access-only-mode-no-devices-no-refresh)) has no device to revoke. To end those too,
an identity or principal implements `HasTokensValidAfter`, with the `ProvidesTokensValidAfter` trait over a nullable
whole-second column you add:

```php
Schema::table('users', function (Blueprint $table) {
    $table->dateTime('tokens_valid_after', 0)->nullable();
});
```

```php
use SineMacula\Laravel\Authentication\Concerns\ProvidesTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;

class User extends Model implements HasTokensValidAfter, Identity, Principal
{
    use ProvidesTokensValidAfter;
}
```

Every bulk revocation of its sessions (including the security-change methods above) then moves its cutoff to the
revocation's second first, except `signOutEverywhere(keepCurrentDevice: true)` from a session without a device, which
keeps the identity's cutoff where it is (see above), and the bearer path rejects a device-less access token whose `iat`
is at or before the identity's or the principal's cutoff (`issued_before_cutoff`). The whole second is cut off, because
a token's whole-second `iat` cannot tell an earlier token from one issued after the call in the same second, so a
device-less token issued in that second is rejected too. Tokens that name a device are not checked against the cutoff
(revoking the device ends them, and the device a sign-out everywhere keeps must keep working). The cutoff only ever
moves forward, with one conditional update on the model's own connection (`invalidateTokensIssuedBefore()`); the column
must be loaded, or reading it throws a `LogicException`, and the column name comes from `getTokensValidAfterName()`.

### Revocation reasons

Every revocation records one of these reasons in the device's `revoked_reason` and in `DeviceRevoked::$reason`
(`RevocationReason`); a bulk revocation reports it in `SignedOutEverywhere::$reason` as well:

| Reason                  | Recorded when                                                                                                               |
|-------------------------|-----------------------------------------------------------------------------------------------------------------------------|
| `signed_out`            | The session signed itself out: `logout()`, `Auth::sessions()->signOut()`                                                    |
| `signed_out_everywhere` | `signOutEverywhere()` ended the identity's sessions                                                                         |
| `revoked`               | The application revoked it: `revokeDevice()`, `revokeDevices()`, `revokePrincipalDevices()`                                 |
| `rotation_reuse`        | A rotated refresh token was replayed, by a refresh or a switch of principal                                                 |
| `password_changed`      | `passwordChanged()`: directly, through `Auth::passwords()->set()` with `CHANGE`, or through `RevokeDevicesOnPasswordChange` |
| `password_reset`        | `passwordReset()`: directly, through a reset or `set()` with `RESET`, or through `RevokeDevicesOnPasswordReset`             |
| `factor_removed`        | `factorRemoved()`, directly or through `RevokeDevicesOnPasskeyRemoval`                                                      |
| `identity_deactivated`  | `identityDeactivated()`, directly or through `RevokeDevicesOnDeactivation`                                                  |
| `principal_deactivated` | `principalDeactivated()`, directly or through `RevokeDevicesOnDeactivation`                                                 |
| `tenant_deactivated`    | `tenantDeactivated()`                                                                                                       |

`revokeDevice()`, `revokeDevices()` and `revokePrincipalDevices()` take the reason as an argument (`REVOKED` in the
examples above); the others set their own.
