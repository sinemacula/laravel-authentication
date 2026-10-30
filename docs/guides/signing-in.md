# Signing in

A guard binds an identity, the principal it acts as and, for a session, the device it lives on. The `Auth` facade
reads what is bound; `attempt()` signs in with a password and binds the guard without a session; the session service
(`Auth::sessions()`) signs in through any sign-in method (a password, a one-time code, a passkey, or one you register
for SSO and the like) or starts a session for an identity something else verified, creates the device and issues the
first token pair. A sign-in can wait for a further factor or for the identity to choose its principal before the session
starts. Every refusal is a result, never an exception, and is reported with `AuthenticationFailed` (see
[Failure outcomes](events.md#failure-outcomes)).

## The `Auth` facade and `attempt()`

Contextual accessors on the standard `Auth` facade:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;

Auth::check();          // bool - same as Laravel
Auth::user();           // Identity|null - same as Laravel

Auth::identity();       // Identity|null   - the authenticated subject
Auth::principal();      // Principal|null  - the acting principal
Auth::device();         // Device|null     - the issuing device
Auth::tenant();         // Tenant|null     - the tenant the principal acts within
Auth::type();           // string|null     - the principal's type, else its tenant's
Auth::scopes();         // list<string>|null - the credential's scope ceiling (null: no credential limits the request)
```

Like `Auth::user()` and `Auth::id()`, each accessor authenticates the request on first access, so they also work on
routes without `auth` middleware. A request is authenticated at most once, whether its token is accepted or rejected,
and after `Auth::logout()` it stays signed out for the rest of the request. `Auth::tenant()` and `Auth::type()` throw a
`TenantUnavailableException` for a principal whose opted-in tenant cannot be loaded, and a `LogicException` for one
loaded without that tenant's key (or polymorphic type). Sign-in, bearer requests and refresh reject such a principal, so
that only happens for one bound through `login()`, `setUser()` or `setPrincipal()`, which skip the activity check.

`setUser()`, which Laravel's `actingAs()` uses, replaces the whole context: it binds the identity with its default
principal (and no device), and throws an `InvalidArgumentException` when the identity has none. Use the guard's
`login($identity, $principal, $device)` to bind a specific principal or a device. `actingAs()` binds the guard for code
that runs in the test itself only: a request the test sends through the HTTP kernel, such as
`$this->actingAs($user, 'api')->getJson('/me')`, rebinds the guard to its own request and starts the context over. In
tests, act through `InteractsWithAuthenticationContext` instead (see [Testing](testing.md)), whose context survives
those requests.

Sign in with credentials through `attempt()`, optionally pinning the principal and device to act as:

```php
$guard->attempt(['email' => $email, 'password' => $password], $membership, $device);
```

`attempt()` signs in through the password sign-in method and the guard's sign-in policies: the audience policy must
allow the `password` method for the guard, the attempt takes a slot from the sign-in limits of the identifier (the
guard's `sign_in.password_identifier` key of the credentials, whatever else they hold) and of the request's IP address,
and only then are the credentials checked, inside the timebox. The identifier key may hold a string, a `Stringable`, an
integer (a numeric column's value, as a JSON body sends it; it is counted as its string form) or a query closure, or be
left out; anything else (a list of addresses, a float, a boolean, `null`) fails as `invalid_credentials` before any
lookup, so request input passed straight through cannot reach accounts the identifier's limit does not count.
`signIn('password', ...)` takes the same strings, `Stringable`s and integers, and refuses anything else as
`invalid_credentials` without a lookup. The password check itself is counted against the account it is made for (see
[Rate limits](configuration.md#rate-limits)). After the password, the identity, the principal and its tenant must be
active, the pins must hold, the audience policy must admit the identity as that principal, the password is rehashed when
its stored hash no longer matches the hasher's algorithm or cost (unless Laravel's `hashing.rehash_on_login` is off),
and the additional-factor policy must not ask for a further factor: `attempt()` cannot hand out a pending sign-in, so a
guard whose policy requires a factor fails it with `additional_factor_required`. A successful attempt gives its slots
back; a failed one keeps them. Every failure fires Laravel's `Failed` and then `AuthenticationFailed` with a reason (see
[Events](events.md#events)). `validate()` checks only the credentials and never rehashes, as with Laravel's own guards;
neither does a bearer request or a refresh, which never see a password.

The pins are verified rather than trusted, because they often come from request input: the principal must be one the
resolver returns for that identifier on the authenticated identity (same class, same identifier) and must belong to that
identity (its `getIdentity()` is the authenticated identity), and the device must be one of the identity's own devices
(through `HasDevices`, looked up the way a bearer `did` is), of this guard (a device of another guard, or of none,
counts as missing), not revoked, with a session that has not ended, and acting as the principal being bound. A pin that
fails either check fails the attempt. `login()` is the trusted entry point: it binds exactly what it is given, so only
pass it a principal and device you have already proven belong to the identity. `setPrincipal()` and `setDevice()` are
trusted binds in the same way: they do not check ownership, activity, revocation or session deadlines, so a principal or
device taken from request input (a header that switches the acting membership, say) must be verified first, as
`attempt()` verifies its pins.

Pinning a principal therefore needs a principal that can report its owner. With `ActsAsPrincipal`, declare the
`identity` relation, as `AppMembership` does above (or override `getIdentityRelationName()`). The owner is read again
from the principal's own stored key, even when Eloquent's strict mode prevents lazy loading, ignoring any identity
relation the resolver already set, and a principal whose owner cannot be read (no relation, or an owner that has been
deleted) fails the attempt.

## Signing in: the session service

Each JWT guard has a session service, `Auth::sessions('api')` (or `Auth::guard('api')->sessions()`), that signs in,
creates the device, issues the first token pair and binds the guard in one call:

```php
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;

// Validating first answers malformed input (a missing field, a list where a
// string belongs) with a 422 rather than a TypeError.
$input = $request->validate([
    'email'         => ['required', 'string'],
    'password'      => ['required', 'string'],
    'client_name'   => ['nullable', 'string'],
    'platform'      => ['nullable', 'string'],
    'refresh_token' => ['nullable', 'string'],
]);

$result = Auth::sessions('api')->signIn(
    'password',
    ['email' => $input['email'], 'password' => $input['password']],
    SignInContext::fromRequest(
        $request,
        clientName: $input['client_name'] ?? null,
        platform: $input['platform'] ?? null,
        refreshToken: $input['refresh_token'] ?? null,
    ),
);

if ($result->isFailed()) {
    // Failed and AuthenticationFailed were dispatched; $result->reason says why.
    if ($result->reason === FailureReason::RATE_LIMITED) {
        // A 429 with Retry-After, as a refused refresh answers, so clients wait.
        throw new ThrottleRequestsException('Too Many Attempts.', null, ['Retry-After' => $result->retryAfter]);
    }

    abort(401);
}

if ($result->requiresFactor()) {
    // No session yet: hand the client the pending token to complete it with.
    return ['pending_token' => $result->pending->token];
}

if ($result->requiresPrincipal()) {
    // No principal named and none by default: the identity chooses one.
    return [
        'choice_token' => $result->choice->token,
        'principals'   => array_map(fn ($principal) => $principal->getPrincipalIdentifier(), $result->choice->principals),
    ];
}

return [
    'access_token'  => $result->session->tokens->accessToken,
    'refresh_token' => $result->session->tokens->refreshToken,
];
```

`signIn()` runs, in order: Laravel's `Attempting` (with only the identifier the method names, never the input); the
guard's audience policy must allow the method (`method_not_allowed`, nothing counted); the identifier and the client's
IP address must have attempts left (`rate_limited`, with the wait); then, inside the credential timebox, the method must
verify the input, the identity, the principal (the one the context names, verified like an `attempt()` pin, or the
resolver's default) and its tenant must be active, and the audience policy must admit the identity as that principal; a
password is rehashed when its hash is outdated; and the additional-factor policy is asked whether a further factor is
required (see [Additional factors](#additional-factors)). Failures are results, not exceptions: Laravel's `Failed` and
then `AuthenticationFailed` report them, with the reason. A method name that is not registered (exactly: `Password` is
not `password`), a method that refuses with any reason but `invalid_credentials`, a misconfigured model and database
errors still throw. A successful sign-in gives its attempt slots back.

`start($identity, $principal, $method, $context)` begins a session for an identity something else verified, such as an
external identity provider. The identity is reloaded through the guard's provider (`identity_unknown` when that does not
return the very same identity), the method must be allowed, the identity, principal and tenant are checked and
admitted, and the additional-factor policy is asked, so a sign-in from outside cannot skip a required factor. No
attempt limit or timebox applies. The principal is given as the argument or on the context, not both.

A session starts on a new device that records the identity, the principal, the guard, the method, the client's name and
platform (from the context, cleaned as the user agent is), the client's IP address and user agent at creation and as its
last use, the digest of the first rotation id, and both deadlines from the guard's lifetimes for the principal. The
device is written and the pair issued in one transaction on the device's connection, so a failure while issuing leaves
no device behind. The guard is then bound (`Validated`, `Login`, `Authenticated`, `PrincipalAssigned` and
`DeviceAuthenticated` fire at once), and `DeviceCreated` and `SignedIn` are dispatched once the device is committed on
its own connection: at once outside a transaction, after your transaction commits inside one, and never when it is
rolled back. Do not roll back around a sign-in: the guard stays bound, and unless `rate_limits.connection` names a
connection of its own the sign-in's attempt counts are rolled back too, so it goes uncounted (see
[Rate limits](configuration.md#rate-limits)). A listener that throws on a bind event fails the
call after the device was committed, so the pair is lost; keep those listeners from throwing or queue them.

A client that signs in again with its current refresh token in the context continues on the same device instead of
creating another: the token proves the client holds that session, even when it has expired. It counts only when it is
the device's current refresh token, validly signed for this guard, for a device the identity owns, of this guard, for
the same principal, and not revoked; anything else simply creates a new device. Continuing a device starts a new session
on it: a new rotation id (the earlier refresh tokens of the device become replays, see
[Refresh token replay](refreshing.md#refresh-token-replay)), both deadlines from now, the method and the client's
description recorded, and `DeviceCreated` not dispatched. If the device changes before it can be continued (a parallel
refresh, say), the sign-in is reconsidered without it: it starts on a new device, or hands out a pending sign-in when
the additional-factor policy now asks for a further factor without the device's trust. The additional-factor policy is
told of the device the client proved, so a factor policy can trust a device it has seen a factor on.

`attempt()` and `login()` remain for code that binds the guard itself; neither creates a device. A session lives on a
device, so the session service signs in only identities that implement `HasDevices`: for any other identity `signIn()`,
`start()` and `complete()` throw a `LogicException` naming its class, since the access token it would issue names a
device the guard could never find again. Access-only guards (identities without `HasDevices`) sign in with `attempt()`
and issue access tokens with `Auth::jwt('api')->issueAccessToken()`.

## Signing in with a one-time code

The package registers `phone_code`, a numeric code sent to a verified phone number, and `email_code`, the same sent to a
verified email address: either signs in with no password, as a primary method or a fallback. Allow it in the guard's
audience, bind a `OneTimeCodeSender` (see [One-time codes](configuration.md#one-time-codes)), and give the identity a
normalised `phone` or `email` column with `HasVerifiableIdentifiers` (see [Identifiers](identity-models.md#identifiers)
and [Identifier verification](identity-models.md#identifier-verification)). The input carries the identifier under its
type's name (`phone`, `email`) and the code under `code`:

```php
'mobile' => [
    'driver'   => 'jwt',
    'provider' => 'staff',
    'audience' => ['methods' => ['phone_code']],
],
```

Two routes of your own ask for a code and sign in with it, through `Auth::codes()` and the session service:

```php
use SineMacula\Laravel\Authentication\Codes\Enums\CodeRequestStatus;
use SineMacula\Laravel\Authentication\Facades\Auth;

Route::post('/codes', function (Request $request) {
    $input  = $request->validate(['phone' => ['required', 'string']]);
    $result = Auth::codes('mobile')->send('phone_code', ['phone' => $input['phone']]);

    // The same answer whether or not anyone has the number.
    return match ($result->status) {
        CodeRequestStatus::RATE_LIMITED       => response()->json(['message' => 'Too Many Attempts.'], 429, ['Retry-After' => $result->retryAfter]),
        CodeRequestStatus::IDENTIFIER_INVALID => response()->json(['message' => 'Enter a number in international format.'], 422),
        CodeRequestStatus::METHOD_NOT_ALLOWED => abort(403),
        CodeRequestStatus::SENT               => response()->json(['expires_at' => $result->expiresAt->toIso8601String()], 202),
    };
});

Route::post('/sign-in/code', function (Request $request) {
    $input  = $request->validate(['phone' => ['required', 'string'], 'code' => ['required', 'string']]);
    $result = Auth::sessions('mobile')->signIn('phone_code', ['phone' => $input['phone'], 'code' => $input['code']]);

    abort_unless($result->isSignedIn(), 401);

    return ['access_token' => $result->session->tokens->accessToken, 'refresh_token' => $result->session->tokens->refreshToken];
});
```

An email address is used in its normal form throughout: a code requested for `Ben@Example.com` is sent to, bound to and
signs in with `ben@example.com`, however either step spells it, and the sender's message carries the normal form; an
address the `email` normaliser rejects (blank, or not valid UTF-8) is `identifier_invalid`. Everything below applies to
`email_code` as to `phone_code`, with the address for the number.

A code request does nothing that depends on whether anyone has the number. The guard must allow the method
(`method_not_allowed`), the number must be one the `phone` normaliser accepts (`identifier_invalid`), the number and the
IP address must have code requests left (`rate_limited`, with the wait), and no code may have been sent to the number
within the resend cooldown (`rate_limited`, with the seconds left); then a code is issued, for anyone's number, and its
delivery queued. The job alone finds the recipient, when it runs: the active identity the guard's provider returns for
the number that holds exactly that number, reports it verified and is not a machine identity. For anyone else it sends
nothing and says nothing, so the response, the statements run and the time taken are the same for a number no one has.
"Exactly" is decided by the package, not your database: the identity's own identifier, in its normal form, must be
byte for byte the requested one. A lookup matches whatever the column's collation does, and MySQL's default
`utf8mb4_unicode_ci` ignores accents, so `ben@examplé.com` (another domain, which anyone can register) finds the holder
of `ben@example.com`; such an identity neither receives the code nor signs in with it. Each refusal is reported
with `AuthenticationFailed` on the `code_request` flow (an invalid number as `invalid_credentials`).

Signing in, the method brings the number to its normal form and requires a code of exactly `length` digits
(`invalid_credentials` otherwise, nothing counted), looks the identity up (an identity that does not hold exactly that
number, as above, counts as none), counts the check against the account's limit as the password method does, and checks
the code against the one sent to the number on this guard. It checks it whether or not anyone has the number, so a guess
at a number no one has counts against, and locks, its code exactly as one at a known number does. A wrong code, a code
used before, a code for another guard, purpose or number, and the right code for a number no one has are
`invalid_credentials`; an expired code and one that used up its attempts are refused as `code_expired` and
`code_exhausted`, which only `AuthenticationFailed` says: the result says `invalid_credentials`. The right code for an
identity whose number is not verified is `identifier_unverified` (the code proved the number is held, so this tells a
guesser nothing). Then the session service does the rest, as for a password: activity, the principal, the audience
policy, a further factor and the device, which records `phone_code`. The code's attempts are counted on its row, on the
storage connection, so a transaction you open there and roll back around a sign-in gives the attempt back; the sign-in
limits on `rate_limits.connection` still count it.

Another identifier type signs in by code once it has a normaliser and a column: register a code method for it, and
allow it.

```php
use SineMacula\Laravel\Authentication\Codes\CodeSignIn;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;

// In a service provider's register():
$this->callAfterResolving(SignInMethodManager::class, static function (SignInMethodManager $methods): void {
    $methods->extend('whatsapp_code', fn ($app) => $app->make(CodeSignIn::class, ['type' => 'whatsapp']));
});
```

## Using passkeys

Each JWT guard has a passkey service, `Auth::passkeys('api')`, for its relying party (see
[Passkeys](configuration.md#passkeys) under Configuration). Passkeys are usernameless: the browser offers the passkeys
it holds for the relying party, the user verifies (biometrics, a PIN), and the passkey names its owner. Every ceremony
is two calls, options and then the browser's answer: the options carry a single-use challenge stored in
`passkey_challenges`, which the answer must use up within its lifetime, through the same guard, for the same relying
party (and, for a registration or a factor, the same identity), whatever it then proves. The routes and responses are
yours.

Allow the method in each guard's audience (`'methods' => ['password', 'passkey']`). A signed-in identity registers a
passkey:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySummary;

// POST /passkeys/options, behind auth:api
$identity = Auth::identity();

return Auth::passkeys('api')->registrationOptions($identity, $identity->email, $identity->name);

// POST /passkeys, behind auth:api
$input = $request->validate([
    'challenge'  => ['required', 'string'],
    'credential' => ['required'],
    'name'       => ['nullable', 'string'],
]);

$outcome = Auth::passkeys('api')->register(
    Auth::identity(),
    $input['challenge'],
    $input['credential'],
    $input['name'] ?? null,
);

return $outcome instanceof PasskeySummary
    ? response()->json($outcome, 201)
    : response()->json(['error' => $outcome->value], 422);
```

The options (`CeremonyOptions`: `challenge`, `options`, `expires_at` as JSON) ask for a discoverable credential with
user verification and no attestation, exclude the identity's passkeys, and hand the browser its options in their
WebAuthn JSON form: pass `options` to `PublicKeyCredential.parseCreationOptionsFromJSON()` and
`navigator.credentials.create()`, and post the credential's `toJSON()` back with the `challenge`. Choose the user name
and display name from the identity's own record, never from the request: the browser shows them. Every passkey an
identity registers for a relying party carries the random user handle its passkeys already had when the options were
handed out, or a new random one when it had none, so registrations whose options were handed out before the first one
completed (on two devices, say) may each get their own; every passkey is checked against its own handle. A handle
carries no personal data and does not depend on `app.key`. `register()` answers a `PasskeySummary`, or a
`PasskeyRegistrationFailure`: `challenge_invalid` (not a live registration challenge of this guard for the identity),
`response_invalid` (malformed, or it does not verify: origin, relying party, user presence and verification, challenge,
algorithm, attestation statement) or `already_registered`. The name is stored cleaned and cut to 255 characters. Under
`attestation: none` a browser may still pass an authenticator's own statement through, so the formats the WebAuthn
library checks on its own (`none`, `packed`, `fido-u2f`, `android-key`, `tpm`, `apple`) are accepted for their internal
consistency, but no certificate chain or metadata is evaluated and every passkey is recorded as unattested. A machine
identity holds no passkey (an `InvalidArgumentException`), and passkeys belong to saved Eloquent identities.

Signing in takes options and then the session service:

```php
// POST /sign-in/passkey/options
return Auth::passkeys('api')->signInOptions();

// POST /sign-in/passkey
$result = Auth::sessions('api')->signIn('passkey', $request->only('challenge', 'credential'));
```

`signInOptions()` names no credential, so the browser offers every passkey it holds for the relying party. Anyone may
ask for them and each request writes a challenge, so each is counted against the client's IP address under the guard's
`passkey_options` limit (see [Rate limits](configuration.md#rate-limits)); past it, a `ThrottleRequestsException`
answers `429` with `Retry-After`. The `passkey` method uses the challenge up, finds the passkey of the guard's relying
party the answer names, loads its owner through the guard's provider as the very model it records, takes a slot of the
owner's account limit, and verifies the assertion: the origin, the relying party, user presence and verification, the
signature, the challenge, and the user handle the passkey was registered under. The session service then decides the
rest, as for any method (see [Signing in: the session service](#signing-in-the-session-service)): no identifier is
named, so only the IP address is limited before the method runs and the verified-identifier requirement does not apply.
A challenge the answer cannot use fails as `passkey_challenge_invalid`, in the result too, since it says nothing about
any account (the client starts again); every other refusal is `invalid_credentials`.

The sign counter guards against a cloned authenticator. With `s` the count stored and `p` the assertion's: `s = 0` and
`p = 0` is accepted and the count stays 0 (most synced passkeys keep no counter); `p > s` is accepted and the count
becomes `p`, with a compare-and-set on `s`, so of two assertions read against one count only one moves it; anything else
(`p <= s` with `s > 0`) is refused as `passkey_counter_regressed`, which only `AuthenticationFailed` says (the result
says `invalid_credentials`). Nothing is written then, so a clone cannot lock the genuine authenticator out; the owner
can remove the passkey. A passkey removed while one of its sign-ins is in flight is refused the same way, with or
without a counter, so no session starts once the removal is committed. A verified passkey records its count, backup
state and last use and dispatches `PasskeyUsed` whether or not the session service then admits its owner: the passkey
was used.

A further-factor package verifies one of an identity's passkeys through the same checks:

```php
// Allows only the identity's passkeys.
$options = Auth::passkeys('api')->factorOptions($identity);

// null once verified, else the reason.
$reason = Auth::passkeys('api')->verifyFactor($identity, $challenge, $credential);
```

`verifyFactor()` answers `null` once the identity's own passkey verified (with `PasskeyUsed`), and otherwise
`passkey_challenge_invalid`, `invalid_credentials` (malformed, not verified, or not the identity's) or
`passkey_counter_regressed`, which the caller already holding the identity may see. It counts nothing and reports no
failure: the factor's outcome is the further-factor package's to limit and report.

`Auth::passkeys('api')->passkeys($identity)` lists the identity's passkeys for the relying party, oldest first, as
`PasskeySummary` (id, name, transports, AAGUID, backup state, created and last used), never the credential id, public
key, user handle or count. `remove($identity, $passkeyId)` removes the identity's passkey of the relying party and
reports `PasskeyRemoved` once committed; it answers whether this call removed it. Finding, listing and removal hold to
the relying party's exact id and the identity's exact type and key, and every ceremony's challenge to its exact
ceremony, guard, relying party and owner, whatever the column's collation counts as equal (`alice` and `Alice` under
MySQL's default `_ci` collations). Removing a passkey removes a way to sign in, but ends no session unless you register
the optional listener:

```php
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authentication\Events\PasskeyRemoved;
use SineMacula\Laravel\Authentication\Listeners\RevokeDevicesOnPasskeyRemoval;

Event::listen(PasskeyRemoved::class, RevokeDevicesOnPasskeyRemoval::class);
```

It ends every session of the identity with `factor_removed`; to keep the current device signed in, call
`Auth::sessions()->factorRemoved($identity, Auth::device())` yourself instead. See `docs/design/passkeys.md`.

## Writing a sign-in method

A sign-in method verifies input the client sends to your sign-in route and answers with the identity it proves, or why
it does not; the session service does everything else (the audience policy, the limits, activity, the principal, a
further factor, the device and the tokens). Use a method for input the package verifies, such as a password, a code
your application issued, or an identity provider's signed assertion the method checks itself. Use `start()` instead
when something outside the session service has already proven the identity, such as an SSO callback your identity
provider's package handles: `start()` runs the same checks after the proof, but no `Attempting`, attempt limit or
timebox, since nothing is guessed there. A method signed in through `signIn()` gets all three. `start()` refuses the
machine credential kinds (`api_key`, `client_credentials`) as the method with an `InvalidArgumentException`, even when
the guard's audience lists them: they authenticate requests and exchanges, never sessions.

```php
use Illuminate\Contracts\Hashing\Hasher;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Sessions\SignInRequest;

final readonly class BadgeSignIn implements SignInMethod
{
    public function __construct(private Hasher $hasher) {}

    public function identifierType(string $guard): ?string
    {
        return 'badge_number';
    }

    public function identifier(string $guard, array $input): ?string
    {
        return is_string($input['badge_number'] ?? null) ? $input['badge_number'] : null;
    }

    public function authenticate(SignInRequest $request): Identity|FailureReason
    {
        $badge    = $this->identifier($request->guard, $request->input);
        $pin      = $request->input['pin'] ?? null;
        $identity = $badge === null ? null : $request->provider->retrieveByCredentials(['badge_number' => $badge]);

        if (! $identity instanceof Identity || ! is_string($pin) || ! $request->reserveAccountAttempt($identity)) {
            return FailureReason::INVALID_CREDENTIALS;
        }

        return $this->hasher->check($pin, $identity->pin_hash) ? $identity : FailureReason::INVALID_CREDENTIALS;
    }
}
```

`identifierType()` names the identifier the method signs in by: the normaliser its limit counts it through, and the
identifier a guard that requires verified identifiers checks. Return `null` for a method that uses no identifier (an
assertion that names the identity itself): then only the IP address is limited and the verified-identifier requirement
does not apply. `identifier()` returns the identifier as the input gives it, for the limits and the failure events,
never to look anyone up. `authenticate()` returns the identity, or `FailureReason::INVALID_CREDENTIALS` for anything the
input did not prove. A method may also answer `identifier_unverified`, but only once its input proved possession of the
identifier (as a one-time code does), and `code_expired`, `code_exhausted`, `passkey_challenge_invalid` or
`passkey_counter_regressed`; `code_expired`, `code_exhausted` and `passkey_counter_regressed` reach the event only, and
the sign-in's result says `invalid_credentials`. Every other reason is the session service's to give, and a method that
returns one throws a `LogicException` (see [Events](events.md#events)). A method must not bind a guard, issue tokens or
write session state, and must hold no state between calls, since the manager keeps one instance per name for as long as
the same application serves: the life of the process, or under Octane the request, whose sandbox builds its own. The
credential timebox pads every refused sign-in, the method's own work included, to `timebox.credentials_microseconds`, so
a method may answer an unknown identifier at once, as the example does; keep the method's worst case under that budget,
and only a method whose work can take longer needs to do the same work whether or not the identifier exists.

A method that looks an identity up and then checks a secret calls `$request->reserveAccountAttempt($identity)` before
checking it, and answers `invalid_credentials` without checking when that returns `false` (the account has used up its
attempts); the session service refuses the sign-in then even if the method returns an identity. A lookup can find one
account by many spellings of its identifier, and through every guard whose provider returns it, so only the account's
own count, held to the most permissive limit among those guards, bounds the guesses at its secret, and at a further
factor its sign-in waits for. Reserve before each secret you check: a method that checks two (a password and a PIN, say)
takes two slots. The slots belong to the sign-in: they are all given back when the session starts, or when its pending
sign-in's completion commits. A completion that your transaction rolls back gives nothing back, since the pending
sign-in it used comes back with the rollback and can be completed again. If giving them back fails after the commit,
the error is reported to your exception handler rather than thrown: the session already stands, and a throw would stop
the commit's later callbacks (another session's events, your own `DB::afterCommit()` work) from running. The slots not
given back stay counted.

To unit-test a method, build its request yourself. `new SignInRequest('kiosk', $provider, $input, $client)` allows every
account check; a fifth argument decides them instead, so `fn (Identity $identity): bool => false` gives you a request
whose accounts have used up their attempts, to test the `invalid_credentials` answer.

Register the method under a lower-case name of its own (a letter, then letters, digits or underscores; `extend()`
refuses anything else, the package's own `password`, `phone_code`, `email_code` and `passkey`, and the machine
credential kinds `api_key` and `client_credentials`; see [Extensibility](extending.md#extensibility)), from a service
provider once the registry resolves (see [Binding order](extending.md#binding-order)), and allow that exact name in each
guard's audience:

```php
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;

// In a service provider's register():
$this->callAfterResolving(SignInMethodManager::class, static function (SignInMethodManager $methods): void {
    $methods->extend('badge', fn ($app) => $app->make(BadgeSignIn::class));
});
```

```php
'kiosk' => [
    'driver'   => 'jwt',
    'provider' => 'staff',
    'audience' => ['methods' => ['badge']],
],
```

```php
$result = Auth::sessions('kiosk')->signIn('badge', $request->only('badge_number', 'pin'));
```

## Additional factors

The additional-factor policy (`Contracts\AdditionalFactorPolicy`, by default one that never asks for a factor; an MFA
package or the application binds its own) is asked about every admitted sign-in, from `signIn()` and from `start()`,
with the guard, identity, principal, tenant, method, client, and the device the client proved it holds, if any. When it
requires a further factor, no session starts: the result's `pending` is a `PendingFactor` whose `token` completes the
sign-in once, for this guard, within `sign_in.pending_ttl_seconds` (five minutes by default). The token is opaque (not a
JWT), so it authenticates no request and refreshes nothing; only the digest of its secret is stored, in
`pending_sign_ins`. The sign-in's attempt slots stay taken while it waits, the one its password check took on the
account included, and are given back only when it completes: a pending sign-in that is discarded or expires leaves them
counted, so each guess at a further factor costs a sign-in attempt. With the password method the guesses are therefore
bounded by the account's own count, whichever spelling of the identifier and whichever guard each sign-in used, held to
the most permissive `per_identifier` limit among the guards that check the account (see
[Rate limits](configuration.md#rate-limits)), so a further factor can be guessed no more often than the password. A
method that does not count the account it checks (see [Writing a sign-in method](#writing-a-sign-in-method)) bounds them
by its identifier's and the IP address's limits only. A sign-in that `start()` holds for a factor took no slots, since
nothing was guessed: the external verifier that proved the identity bounds how often it can be repeated.

The code that verifies the factor looks the pending sign-in up, verifies the factor for its identity and principal, and
only then completes it. Possessing the token proves nothing about the factor: `complete()` is a trusted entry point,
like `start()`.

```php
['pending_token' => $token, 'code' => $code] = $request->validate([
    'pending_token' => ['required', 'string'],
    'code'          => ['required', 'string'],
]);

$sessions = Auth::sessions('api');
$pending  = $sessions->pending($token);

if ($pending === null) {
    abort(401);
}

if (! $factors->verify($pending->identity, $pending->principal, $code)) {
    // One guess per pending sign-in; another needs a new sign-in, which counts
    // against the sign-in limits.
    $sessions->discard($token);

    abort(401);
}

$result = $sessions->complete($token);
```

Holding a sign-in for a factor is its outcome, so it is reported: `AdditionalFactorRequired` carries the guard,
identity, principal, tenant, the device the client proved (if any), the method, the client and the expiry, never the
token, and is dispatched once the pending sign-in is committed (after your transaction, and never if you roll it back).

`discard()` uses a pending sign-in up without starting a session, whatever has changed about its identity since; call it
when the factor fails, so each pending sign-in allows one guess. It returns whether the token named a live pending
sign-in of this guard and, when it did, reports the failure of the sign-in that waited: Laravel's `Failed` and then
`AuthenticationFailed` with `additional_factor_failed`, the method, the discarding request's client and the identity
(when the guard's provider still returns it; no principal). A token that discards nothing reports nothing.

`pending()` never uses the pending sign-in up, and returns `null` for any token that does not name a live one of this
guard whose identity and principal still resolve as it recorded them. `complete()` uses it up whatever the outcome,
with a delete only one completion can make, checks it again in the same transaction (the method still allowed, the
identity, principal and tenant active, and the audience policy admitting them with the identifier type the sign-in
used; the factor policy is not asked again), and starts the session on the device the client proved it holds when that
is unchanged, otherwise on a new one, which records the client the sign-in came from as its creation and the completing
request's client as its last use. The events of a completion, `AuthenticationFailed` included, carry the completing
request's client. A token that completes nothing fails as `pending_invalid`, without saying why.

Pending sign-ins that were never completed expire; schedule their pruning with the rate limit counters' (see
[Rate limits](configuration.md#rate-limits)).

## Choosing a principal

A sign-in (`signIn()` or `start()`) that names no principal, for an identity whose resolver has no default principal,
waits for the identity to choose one when it may sign in as any: the result `requiresPrincipal()`, and its `choice` is a
`PrincipalChoice` with a single-use `token`, the guard, the identity, the method, the expiry
(`sign_in.pending_ttl_seconds`, as for a factor) and the `principals` it may choose from. Those are the identity's
`principals()`, read on the write connection, that are active, act within an active tenant (or none), and are admitted
by the guard's audience policy (for an identity that is its own principal, the resolver's default).
`Auth::sessions('api')->principals($identity, $identifierType)` lists them the same way; a switch screen passes the
type of identifier its session's sign-in used, `Auth::guard('api')->device()?->getSignInIdentifierType()`, so it lists
only the targets the audience policy lets that session switch to (without a type, the list ignores the identifier and
may hold targets a switch refuses). An identity with none fails as
`principal_unresolved`, as before. The choice itself, and every later look-up of it, is admitted with the identifier
type the sign-in used, as a sign-in naming a principal would be, so a principal your audience policy refuses to that
identifier is neither offered nor listed, and a guard with `require_verified_identifier` offers no choice, and lists no
principal, to an identity whose identifier is unverified: the sign-in fails as `identifier_unverified` with nothing
stored or reported. `attempt()` never waits for a choice.

The choice is stored like a pending factor, in `pending_sign_ins` with `purpose = principal_choice` and no principal,
with the device the client proved it holds (whatever principal that device records) and the sign-in's attempt slots,
which stay taken until a session starts. `PrincipalChoiceRequired` reports it once committed, with the identity, method,
client and that device, never the token or the list.

```php
['choice_token' => $token, 'principal' => $id] = $request->validate([
    'choice_token' => ['required', 'string'],
    'principal'    => ['required', 'string'],
]);

$sessions = Auth::sessions('api');
$choice   = $sessions->choice($token); // null: unknown, expired, used, or not this guard's

$principal = collect($choice?->principals ?? [])
    ->first(fn ($principal) => (string) $principal->getPrincipalIdentifier() === $id);

if ($principal === null) {
    abort(401);
}

$result = $sessions->choose($token, $principal);
```

`choice()` never uses the choice up. `choose()` uses it up whatever the outcome, with a delete only one call can make,
then admits the chosen principal as any sign-in would: the method still allowed, the principal resolved through the
resolver's hinted path as the very one named and the identity's own (`principal_mismatch`), active, in an active tenant,
and admitted by the audience policy with the identifier type the sign-in used. The additional-factor policy is then
asked: a required factor turns the choice into a pending factor for the chosen principal, carrying the same attempt
slots (complete it as above). Otherwise the session starts, on the device the client proved when that device records the
chosen principal and is unchanged, else on a new one, and the slots are given back once committed. A token that
continues no live choice of this guard fails as `pending_invalid`; `pending()` and `complete()` refuse choice tokens,
and `choice()` and `choose()` refuse factor tokens. `discard()` takes either: a discarded choice reports
`AuthenticationFailed` with `principal_choice_abandoned`.

## Enumeration resistance

No response, and no response time, tells a client whether an identifier belongs to anyone. Routes and responses are
yours; what the package guarantees for each method and helper, and what its tests hold it to, is:

| Flow                      | Same outcome for an unknown identifier                                                                                                                                                              | Delivery                                          | Timing                                                                                                       |
|---------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| Password sign-in          | `invalid_credentials` for an unknown identifier, a wrong password and a locked account                                                                                                              | None                                              | Padded to the credential timebox                                                                             |
| Code request              | A code is issued for any identifier: same status, expiry, cooldown, limits and statements                                                                                                           | Queued job (after the response on `sync`)         | No identity work at all, so nothing to pad                                                                   |
| Code sign-in              | `invalid_credentials` for an unknown identifier, a wrong, expired, exhausted or used code, and a locked account                                                                                     | None                                              | Padded to the credential timebox                                                                             |
| Verification by code      | Not applicable: the caller holds the identity                                                                                                                                                       | Queued job (after the response on `sync`)         | Not applicable                                                                                               |
| Reset request             | A token or code is issued for any identifier: same status, expiry, cooldown, limits and statements                                                                                                  | Queued job (after the response on `sync`)         | No identity work at all, so nothing to pad                                                                   |
| Reset submission          | `invalid` for an unknown identifier and for a wrong, expired, exhausted, used or ineligible proof (an inactive, machine or unverified holder); the policy's verdict does not depend on the identity | None                                              | Padded to the credential timebox; a held address adds only the lock of its row                               |
| Identifier change request | Not applicable: the caller holds the identity; the answer never depends on whether another identity holds the new identifier                                                                        | Queued job for a code; a link is returned to send | Not applicable                                                                                               |
| Passkey sign-in           | No identifier to probe: an unknown, foreign or ownerless passkey, a bad signature or user handle, a regressed counter and a locked account all answer `invalid_credentials`                         | None                                              | Padded to the credential timebox, owner looked up or not; sign-in options do no identity work                |
| API key                   | `credential_invalid` for a malformed key, an unknown public part and a wrong secret; the key's status only once the secret verifies                                                                 | None                                              | No hasher; an unknown public part is checked against a dummy digest, so the work and statements are the same |
| Client credentials        | 401 `invalid_client` with the same body for every client failure (a Basic challenge only to a Basic client); `slow_down` counts the client id as given, when limited                                | None                                              | As API key                                                                                                   |

The code request's answer for a number nobody has is `sent`, with the same expiry as any other; only the delivery job
looks the number up, and it sends nothing to an unknown, unverified, inactive or machine identity, or to one that holds
only a look-alike of it. Answer `sent` the same way whatever happens next, and do not tell the client whether a message
went out.
