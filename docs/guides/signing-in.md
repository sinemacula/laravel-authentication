# Signing in

A guard binds an identity, the principal it acts as and the session, when there is one. The `Auth` facade
reads what is bound; `attempt()` signs in with a password and binds the guard without a session; the session service
(`Auth::sessions()`) signs in through any sign-in method (a password, a one-time code, a passkey, or one you register
for SSO and the like) or starts a session for an identity something else verified, creates the session and issues the
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
Auth::session();        // Session|null    - the bound session
Auth::tenant();         // Tenant|null     - the active tenant the request acts in
Auth::scopes();         // list<string>|null - the credential's scope ceiling (null: no credential limits the request)
```

Like `Auth::user()` and `Auth::id()`, each accessor authenticates the request on first access, so they also work on
routes without `auth` middleware. A request is authenticated at most once, whether its token is accepted or rejected,
and after `Auth::logout()` it stays signed out for the rest of the request. `Auth::tenant()` is the active tenant: the one
the request's session records, or the principal's own for a token without a session, read when the request is
authenticated and held until the guard is bound again. For a principal bound through `login()`, `setUser()` or
`setPrincipal()`, which skip the activity check, it is the bound session's recorded tenant, or with no session the
principal's own, even when it is inactive. `null` only ever means the request acts in no tenant: when the tenant such a
bind found cannot be loaded (deleted, or no longer resolving), `Auth::tenant()` throws `TenantUnavailableException`, so
code that scopes by it never takes a tenanted context for a platform-wide one. A principal loaded without its tenant's
key (or polymorphic type) is a misconfiguration, and the bind throws its `LogicException`.

`setUser()`, which Laravel's `actingAs()` uses, replaces the whole context: it binds the identity with its default
principal (and no session), and throws an `InvalidArgumentException` when the identity has none. Use the guard's
`login($identity, $principal, $session)` to bind a specific principal or a session. `actingAs()` binds the guard for
code that runs in the test itself only: a request the test sends through the HTTP kernel, such as
`$this->actingAs($user, 'api')->getJson('/me')`, rebinds the guard to its own request and starts the context over. In
tests, act through `InteractsWithAuthenticationContext` instead (see [Testing](testing.md)), whose context survives
those requests.

Sign in with credentials through `attempt()`, optionally pinning the principal and session to act as:

```php
$guard->attempt(['email' => $email, 'password' => $password], $membership, $session);
```

`attempt()` signs in through the password sign-in method and the guard's sign-in policies: the application policy must
allow the `password` method for the guard, the attempt takes a slot from the sign-in limits of the identifier (the
guard's `sign_in.password_identifier` key of the credentials, whatever else they hold) and of the request's IP address,
and only then are the credentials checked, inside the timebox. The identifier key may hold a string, a `Stringable`, an
integer (a numeric column's value, as a JSON body sends it; it is counted as its string form) or a query closure, or be
left out; anything else (a list of addresses, a float, a boolean, `null`) fails as `invalid_credentials` before any
lookup, so request input passed straight through cannot reach accounts the identifier's limit does not count.
`signIn('password', ...)` takes the same strings, `Stringable`s and integers, and refuses anything else as
`invalid_credentials` without a lookup. The password check itself is counted against the account it is made for (see
[Rate limits](configuration.md#rate-limits)). After the password, the identity, the principal and its own tenant must be
active, the application policy must admit the identity (`admitIdentifier()`), `ApplicationAccess` must let the principal
use the application (`principal_ineligible`), the pins must hold, and the active tenant (the principal's own, or the one
a pinned session records) must be one `TenantAccess` lets it act in and active (`tenant_ineligible`, `tenant_inactive`).
The password is rehashed when its stored hash no longer matches the hasher's algorithm or cost (unless Laravel's
`hashing.rehash_on_login` is off). `attempt()` cannot leave a session pending, so the additional-factor policy must not
ask for a further factor (`additional_factor_required`), and the active tenant's authentication policy, judged against
the password, must ask for neither a connection (`sso_required`) nor a further factor (`additional_factor_required`). A
successful attempt gives its slots back; a failed one keeps them. Every failure fires Laravel's `Failed` and then
`AuthenticationFailed` with a reason (see [Events](events.md#events)). `validate()` checks only the credentials and
never rehashes, as with Laravel's own guards; neither does a bearer request or a refresh, which never see a password.

The pins are verified rather than trusted, because they often come from request input: the principal must be one the
resolver returns for that identifier on the authenticated identity (same class, same identifier) and must belong to that
identity (its `getIdentity()` is the authenticated identity), and the session must be one of the identity's own sessions
(through `HasSessions`, looked up the way a bearer `sid` is), of this guard (a session of another guard, or of none,
counts as missing), not revoked, not ended, and acting as the principal being bound. A pin that fails either check fails
the attempt. `login()` is the trusted entry point: it binds exactly what it is given, so only pass it a principal and
session you have already proven belong to the identity. `setPrincipal()` and `setSession()` are trusted binds in the
same way: they do not check ownership, activity, revocation or session deadlines, so a principal or session taken from
request input (a header that switches the acting membership, say) must be verified first, as `attempt()` verifies its
pins.

Pinning a principal therefore needs a principal that can report its owner. With `ActsAsPrincipal`, declare the
`identity` relation, as `AppMembership` does above (or override `getIdentityRelationName()`). The owner is read again
from the principal's own stored key, even when Eloquent's strict mode prevents lazy loading, ignoring any identity
relation the resolver already set, and a principal whose owner cannot be read (no relation, or an owner that has been
deleted) fails the attempt.

## Signing in: the session service

Each JWT guard has a session service, `Auth::sessions('api')`, that signs in, creates the session, issues the first
token pair and binds the guard in one call. The manager builds a new one from the guard on each call; the guard itself
has no `sessions()` method, so code written as `Auth::guard('api')->sessions()` becomes `Auth::sessions('api')`:

```php
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;
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
        throw new ThrottleRequestsException(__('Too Many Attempts.'), null, ['Retry-After' => $result->retryAfter]);
    }

    abort(401);
}

if ($result->isPending()) {
    // No token yet: the session waits on a further factor, a choice of
    // principal, or both (see Pending sessions).
    return SecretResponse::json([
        'status'             => 'pending',
        'id'                 => $result->pending->id,
        'requires'           => array_map(fn ($requirement) => $requirement->value, $result->pending->requires),
        'pending_credential' => $result->credential,
    ]);
}

return SecretResponse::json([
    'access_token'  => $result->session->tokens->accessToken,
    'refresh_token' => $result->session->tokens->refreshToken,
]);
```

`signIn()` runs, in order: Laravel's `Attempting` (with only the identifier the method names, never the input); the
application policy must allow the method (`method_not_allowed`, nothing counted); the identifier and the client's IP
address must have attempts left (`rate_limited`, with the wait); then, inside the credential timebox, the method must
verify the input and the identity must be admitted; a password is rehashed when its hash is outdated; and the sign-in
follows the order [Pending sessions](#pending-sessions) sets out: the principals, the one selected or a choice, the
identity-level factor policy, the selected principal's active tenant, and that tenant's authentication policy
(`sso_required`, or a further factor owed). Failures are results, not exceptions: Laravel's `Failed` and then
`AuthenticationFailed` report them, with the reason. A method name that is not registered (exactly: `Password` is not
`password`), a method that refuses with any reason but `invalid_credentials`, a misconfigured model and database errors
still throw. A sign-in whose session starts active gives its attempt slots back.

`start($identity, $principal, $method, $context, $provenance)` begins a session for an identity something else verified,
such as an external identity provider. The identity is reloaded through the guard's provider (`identity_unknown` when
that does not return the very same identity), the method must be allowed, and the sign-in then follows the same order,
so a sign-in from outside cannot skip a required factor or the choice of principal. No attempt limit or timebox applies.
The principal is given as the argument or on the context, not both.

When an external provider verified the identity, pass what your server-side code checked as a `Proofs\Provenance`: the
connection (the configured provider) and its tenant, when the provider authenticated the identity, its deadline for its
own session (SAML `SessionNotOnOrAfter`), and the version of the enforcement or policy you checked. The session's first
proof is then the provider's: the connection as an `external_provider` channel, the private `amr` value
`urn:sinemacula:amr:external_provider` (RFC 8176 names none for it; the provider's own values are its package's to
carry), and the provider's authentication time (now, when it gave none or one after now). The provenance is recorded
with the session and never rewritten, and the provider's deadline is folded into the context's (see [A sign-in's own
deadline](#a-sign-ins-own-deadline)), so the earlier of the two caps the session's absolute deadline. Never build a
provenance from what the client sent. Without one, the first proof names no channel and no `amr` value, timed now.

```php
use SineMacula\Laravel\Authentication\Proofs\Provenance;

$result = Auth::sessions('api')->start($identity, null, 'sso', null, new Provenance(
    connectionId: $connection->id,
    tenantId: $connection->tenant_id,
    providerAuthenticatedAt: $assertion->authenticatedAt,
    sessionNotAfter: $assertion->sessionNotOnOrAfter,
    policyVersion: $enforcement->version,
));
```

Every sign-in starts a new session that records the identity, the principal, the guard, the method, the client's name
and platform (from the context, cleaned as the user agent is), the client's IP address and user agent at creation and as
its last use, the digest of the first rotation id, both deadlines from the guard's lifetimes (the absolute one capped at
the sign-in's own deadline, if it gives one, and `null` when neither sets one), and the proof of the first factor the
sign-in verified, with the time it was verified (see [Proofs and provenance](sessions.md#proofs-and-provenance)). The
session, its proofs and provenance are written and the pair issued in one transaction on the session's connection, so a
failure while issuing leaves none of them behind. `SessionCreated` and `SignedIn` are then scheduled for the session's
commit on its own connection, and after them the guard's bind (`Validated`, `Login`, `Authenticated`,
`PrincipalAssigned` and `SessionAuthenticated`) and then the give-back of the sign-in's attempt slots. Outside a
transaction the session is already committed, so all three run at once, the events before the bind: a listener on them
reads the event's context, not the guard. Inside your transaction all three wait for it to commit, in that order, and
none runs when it is rolled back: a sign-in you roll back never binds the guard and gives no slots back. The result
answers at once either way, with the pair (a cookie application's refresh cookie in it, which the package never queues:
attach it only once your transaction has committed). A bind that waited for your commit binds only while the guard
still serves the request that signed in, and reads the session again first, binding it only while it is still that
session, live and active, so a session your transaction revoked or returned to pending after signing it in is never
bound. Unless `rate_limits.connection` names a connection of its own, a rollback rolls the sign-in's attempt counts back
too, so it goes uncounted (see [Rate limits](configuration.md#rate-limits)). A listener that throws on a bind event
fails the call (or your commit, inside a transaction), so the pair is lost, but cannot keep the session from being
reported, which comes first, and leaves the sign-in's slots counted. Keep those listeners from throwing or queue them.

Every sign-in starts a new session, with a new id and a new rotation id. A client that signs in again with its current
refresh token in the context proves it holds its previous session, even when that has expired, and the sign-in then
revokes the previous session as `superseded` in the same transaction that creates the new one. Passing the refresh token
is how an application opts in: without it nothing is revoked, however alike the IP address, user agent, client name or
platform are, and the previous session lives on until it expires or is revoked. The token counts only when it is the
session's current refresh token, validly signed for this guard, for a session the identity owns, of this guard, for the
same principal, active (not returned to pending) and not revoked; anything else proves nothing and revokes nothing. The
previous session's access tokens stop working at once and its refresh token is refused as `session_revoked`; the new
session keeps the client name and platform the previous one recorded when the sign-in gives none. Once committed,
`SessionRevoked` (`superseded`) is dispatched for the previous session before the new session's `SessionCreated` and
`SignedIn`. If the session changes before it can be revoked (a parallel refresh, say), the sign-in is reconsidered
without it and revokes nothing: it starts on a new session, or leaves it pending when the additional-factor policy now
asks for a further factor without the session's trust. A pending session supersedes the proven session only when it
first activates. The additional-factor policy is told of the session the client proved; the new session has a new id, so
nothing a factor package kept about the previous session carries over to it.

### A sign-in's own deadline

A sign-in may cap the session it starts at a deadline of its own, such as the session deadline an external identity
provider reports (`SessionNotOnOrAfter`, say), on the context's `notAfter` (cut to the whole second):

```php
$context = SignInContext::fromRequest($request)->withNotAfter($providerSessionEndsAt);

$result = Auth::sessions('api')->start($identity, null, 'sso', $context);
```

The session's absolute deadline is then the earlier of the deadline and the application's absolute limit, or the
deadline alone when the application sets none (see [Token and session
lifetimes](configuration.md#token-and-session-lifetimes)), and its idle deadline is never later. A refresh, a switch of
principal, a step-up and a reauthentication never move it. `withNotAfter()` keeps the earlier of the context's deadline
and the one given, so a deadline is only ever lowered, and `null` changes nothing. A sign-in whose deadline is this
second or earlier is refused as `session_expired` (reported as any failed sign-in) before the additional-factor policy
is asked, a choice is offered or anything is written. A pending session keeps its deadline, and its credential expires
no later than it.
`fromRequest()` never sets a deadline: it is the application's, or a trusted adapter's, to supply, never the client's.

`attempt()` and `login()` remain for code that binds the guard itself; neither creates a session. A session is a stored
row, so the session service signs in only identities that implement `HasSessions`: for any other identity `signIn()`,
`start()` throw a `LogicException` naming its class, since the access token it would issue names a
session the guard could never find again. Access-only guards (identities without `HasSessions`) sign in with `attempt()`
and issue access tokens with `Auth::jwt('api')->issueAccessToken()`, a `Secret` to send as the others are (see [Secrets
in responses](#secrets-in-responses)).

### Secrets in responses

Every secret the package hands out is a `Secrets\Secret`: the access and refresh tokens of a `TokenPair` (and the access
token `Auth::jwt()` issues), the pending credential of a `SignInResult`, `RefreshResult` or `SwitchResult`, the access
token of a step-up, a reauthentication or a client credentials grant, the key of an `IssuedApiKey`, the code of a
`OneTimeCodeMessage`, the token of a `PasswordResetLink`, an identifier change's signed link and a verification link.
The plaintext leaves only through `reveal()`, where you send it. Casting a secret to a string, encoding it as JSON
(`json_encode()`, `response()->json()`), serialising it (into a queued job, a cache, the session) or unserialising one
throws `Exceptions\SecretNotRevealedException`, a `LogicException`: a bug in the calling code, never a result to handle.
`var_dump`, `print_r` and Laravel's `dump` and `dd` show `[redacted]` (`Secret::REDACTED`), and a stack trace that
records arguments holds the object, never the plaintext. The values your code hands in (a password, the input a client
sent, a refresh token or pending credential a request carried) are strings, covered by `#[\SensitiveParameter]`. A
method that takes a token or credential back (`refresh()`, `switchTo()`, `signOutWith()`, `pending()`, `satisfy()`,
`choose()`, `discard()`) takes either that string or the `Secret` the package returned, so there is nothing to reveal
to hand one back.

Answer with `Secrets\SecretResponse::json($data, $status, $headers)`: it reveals every `Secret` in `$data`, at any depth
of arrays, and marks the response `Cache-Control: no-store` and `Pragma: no-cache`, replacing any caching headers, so no
browser, proxy or shared cache keeps a copy. `SecretResponse::withoutStoring($response)` marks a response you built
yourself the same way. To cover every response of a route, the `401` of `auth`, a refused route binding's `404`, an
error your controller raises and the secrets other packages return (a factor's secret, recovery codes) included, list
the `authentication.no-store` middleware on the route:

```php
Route::middleware(['auth:api', 'authentication.no-store'])->post('/factors', AddFactorController::class);
```

The middleware is opt-in per route and reads no body. The package puts it first in the HTTP kernel's middleware
priority, so wherever a route lists it, it runs outside every other route middleware the kernel sorts (`auth`,
`SubstituteBindings`, throttling) and sets the headers last: nothing a later middleware does can drop them. The kernel
sorts only middleware in its priority list, so list it before any middleware of your own that is not in that list.
Global middleware runs outside route middleware altogether. An application that sets the whole priority list itself
with `withMiddleware()`'s `priority()` keeps the package's entry, which is added once the kernel is resolved; one that
replaces the list later must put `SineMacula\Laravel\Authentication\Http\Middleware\NoStore` first itself.

## Signing in with a one-time code

The package registers `phone_code`, a numeric code sent to a verified phone number, and `email_code`, the same sent to a
verified email address: either signs in with no password, as a primary method or a fallback. Allow it in the guard's
`application.methods`, bind a `OneTimeCodeSender` (see [One-time codes](configuration.md#one-time-codes)), and give the
identity a normalised `phone` or `email` column with `HasVerifiableIdentifiers` (see
[Identifiers](identity-models.md#identifiers) and [Identifier
verification](identity-models.md#identifier-verification)). The input carries the identifier under its type's name
(`phone`, `email`), the code under `code`, and the id of the challenge the code was sent for, which the request
answers, under `challenge`:

```php
'mobile' => [
    'driver'      => 'jwt',
    'provider'    => 'staff',
    'application' => ['methods' => ['phone_code']],
],
```

Two routes of your own ask for a code and sign in with it, through `Auth::codes()` and the session service:

```php
use SineMacula\Laravel\Authentication\Codes\Enums\CodeRequestStatus;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;

Route::post('/codes', function (Request $request) {
    $input  = $request->validate(['phone' => ['required', 'string']]);
    $result = Auth::codes('mobile')->send('phone_code', ['phone' => $input['phone']]);

    // The same answer whether or not anyone has the number.
    return match ($result->status) {
        CodeRequestStatus::RATE_LIMITED,
        CodeRequestStatus::DELIVERIES_EXHAUSTED => response()->json(['message' => __('Too Many Attempts.')], 429, ['Retry-After' => $result->retryAfter]),
        CodeRequestStatus::IDENTIFIER_INVALID   => response()->json(['message' => 'Enter a number in international format.'], 422),
        CodeRequestStatus::METHOD_NOT_ALLOWED,
        CodeRequestStatus::LOCKED,
        CodeRequestStatus::REFUSED              => abort(403),
        CodeRequestStatus::SENT                 => response()->json(['challenge' => $result->challengeId, 'expires_at' => $result->expiresAt->toIso8601String()], 202),
    };
});

Route::post('/sign-in/code', function (Request $request) {
    $input  = $request->validate(['phone' => ['required', 'string'], 'challenge' => ['required', 'string'], 'code' => ['required', 'string']]);
    $result = Auth::sessions('mobile')->signIn('phone_code', ['phone' => $input['phone'], 'challenge' => $input['challenge'], 'code' => $input['code']]);

    abort_unless($result->isSignedIn(), 401);

    return SecretResponse::json(['access_token' => $result->session->tokens->accessToken, 'refresh_token' => $result->session->tokens->refreshToken]);
});
```

An email address is used in its normal form throughout: a code requested for `Ben@Example.com` is sent to, bound to and
signs in with `ben@example.com`, however either step spells it, and the sender's message carries the normal form; an
address the `email` normaliser rejects (blank, or not valid UTF-8) is `identifier_invalid`. Everything below applies to
`email_code` as to `phone_code`, with the address for the number.

A code request does nothing that depends on whether anyone has the number. The guard must allow the method
(`method_not_allowed`), the number must be one the `phone` normaliser accepts (`identifier_invalid`), the number and the
IP address must have code requests left (`rate_limited`, with the wait), no code may have been sent to the number within
the resend cooldown (`rate_limited`, with the seconds left), and the number's delivery window must allow another
delivery (`deliveries_exhausted`, with the wait until the window ends); then a code is issued, for anyone's number, and
its delivery queued. The answer carries the challenge's id: a request after the cooldown, while the challenge lives, is
a resend of the same challenge (the same id, its attempts kept, a new code that replaces the previous one at once, never
past the window's end), and otherwise a new challenge, under the same delivery cap. The job alone finds the recipient,
when it runs: the active identity the guard's provider returns for the number that holds exactly that number, reports it
verified and is not a machine identity. For anyone else it sends nothing and says nothing, so the response, the
statements run and the time taken are the same for a number no one has. "Exactly" is decided by the package, not your
database: the identity's own identifier, in its normal form, must be byte for byte the requested one. A lookup matches
whatever the column's collation does, and MySQL's default `utf8mb4_unicode_ci` ignores accents, so `ben@examplé.com`
(another domain, which anyone can register) finds the holder of `ben@example.com`; such an identity neither receives the
code nor signs in with it. Each refusal is reported with `AuthenticationFailed` on the `code_request` flow (an invalid
number as `invalid_credentials`).

Signing in, the method brings the number to its normal form and requires a code of exactly `length` digits and a
challenge id the package issues (`invalid_credentials` otherwise, nothing counted), looks the identity up (an identity
that does not hold exactly that number, as above, counts as none), counts the check against the account's limit as the
password method does, and checks the code against the one sent to the number on this guard. It checks it whether or not
anyone has the number, so a guess at a number no one has counts against, and locks, its code exactly as one at a known
number does. A code naming another challenge than the live one is `invalid_credentials` and spends no attempt. A wrong
code, a code used before, a code for another guard, purpose or number, and the right code for a number no one has are
`invalid_credentials`; an expired code and one that used up its attempts are refused as `code_expired` and
`code_exhausted`, which only `AuthenticationFailed` says: the result says `invalid_credentials`. The right code for an
identity whose number is not verified is `identifier_unverified` (the code proved the number is held, so this tells a
guesser nothing). Then the session service does the rest, as for a password: activity, the principal, the application
policy, a further factor and the session, which records `phone_code`. The code's attempts are counted on its row, on the
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

Allow the method in each application's `application.methods` (`'methods' => ['password', 'passkey']`). A signed-in
identity registers a passkey:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;

// POST /passkeys/options, behind auth:api
$identity = Auth::identity();

return Auth::passkeys('api')->registrationOptions($identity, $identity->email, $identity->name);

// POST /passkeys, behind auth:api
$input = $request->validate([
    'challenge'  => ['required', 'string'],
    'credential' => ['required'],
    'name'       => ['nullable', 'string'],
]);

$result = Auth::passkeys('api')->register(
    Auth::identity(),
    $input['challenge'],
    $input['credential'],
    $input['name'] ?? null,
);

return $result->isRegistered()
    ? response()->json($result->passkey, 201)
    : response()->json(['error' => $result->status->value], 422);
```

The options (`CeremonyOptions`: `challenge`, `options`, `expires_at` as JSON) ask for a discoverable credential with
user verification and no attestation, exclude the identity's passkeys, and hand the browser its options in their
WebAuthn JSON form: pass `options` to `PublicKeyCredential.parseCreationOptionsFromJSON()` and
`navigator.credentials.create()`, and post the credential's `toJSON()` back with the `challenge`. Choose the user name
and display name from the identity's own record, never from the request: the browser shows them. Every passkey an
identity registers for a relying party carries the random user handle its passkeys already had when the options were
handed out, or a new random one when it had none, so registrations whose options were handed out before the first one
completed (on two sessions, say) may each get their own; every passkey is checked against its own handle. A handle
carries no personal data and does not depend on `app.key`. `register()` answers a `PasskeyRegistration` whose `status`
(`PasskeyRegistrationStatus`) is `registered`, with the passkey's `PasskeySummary` in `passkey`, or `challenge_invalid`
(not a live registration challenge of this guard for the identity), `response_invalid` (malformed, or it does not
verify: origin, relying party, user presence and verification, challenge, algorithm, attestation statement) or
`already_registered`, with no passkey. The name is stored cleaned and cut to 255 characters. Under
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
answers `429` with `Retry-After` and a [localisable](installation.md#localising-messages) message. The `passkey` method
uses the challenge up, finds the passkey of the guard's relying party the answer names, loads its owner through the
guard's provider as the very model it records, takes a slot of the owner's account limit, and verifies the assertion:
the origin, the relying party, user presence and verification, the signature, the challenge, and the user handle the
passkey was registered under. The session service then decides the rest, as for any method (see [Signing in: the session
service](#signing-in-the-session-service)): no identifier is named, so only the IP address is limited before the method
runs and the verified-identifier requirement does not apply. A challenge the answer cannot use fails as
`passkey_challenge_invalid`, in the result too, since it says nothing about any account (the client starts again); every
other refusal is `invalid_credentials`.

The sign counter guards against a cloned authenticator. With `s` the count stored and `p` the assertion's: `s = 0` and
`p = 0` is accepted and the count stays 0 (most synced passkeys keep no counter); `p > s` is accepted and the count
becomes `p`, with a compare-and-set on `s`, so of two assertions read against one count only one moves it; anything else
(`p <= s` with `s > 0`) is refused as `passkey_counter_regressed`, which only `AuthenticationFailed` says (the result
says `invalid_credentials`). Nothing is written then, so a clone cannot lock the genuine authenticator out; the owner
can remove the passkey. A passkey removed while one of its sign-ins is in flight is refused the same way, with or
without a counter, so no session starts once the removal is committed. A verified passkey records its count, backup
state and last use and dispatches `PasskeyUsed` whether or not the session service then admits its owner: the passkey
was used.

A further-factor package verifies one of the passkeys it associated as an identity's factors through the same checks,
on a ceremony bound to the session and purpose it verifies for:

```php
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;

$binding = new ProofBinding($identity, 'api', $pending->id, Purpose::SIGN_IN);

// Allows only the credentials named that the identity holds; null when it holds none of them.
$options = Auth::passkeys('api')->factorOptions($identity, $binding, $credentialIds);

$result = Auth::passkeys('api')->verifyFactor($identity, $binding, $challenge, $credential);

if ($result->isFailed()) {
    // $result->reason
}

$observed = $result->assertion->observed;
```

`factorOptions()` takes the factor package's binding, which must name the identity, this guard and a session (an
`InvalidArgumentException` otherwise), and the credential ids it associated, each as canonical unpadded base64url (the
`credentialId` a registration or an assertion hands it). It allows only those of the identity's passkeys for the
relying party, compared exactly, and answers `null`, writing nothing, when none is left: an empty list would let the
browser offer any credential it holds. It requires user verification, or only prefers it when the factor package passes
`false` as its last argument. Its challenge is bound to the binding's session and purpose as well as the guard, the
relying party and the identity.

`verifyFactor()` answers a `PasskeyFactorResult`: verified once one of the passkeys the challenge allowed verified for
the identity (with `PasskeyUsed`), its `assertion` a `PasskeyFactorAssertion` (`passkeyId`, `credentialId`, `observed`,
`assertedAt` and the `passkey`'s `PasskeySummary` as the use left it), or failed with its `reason`:
`passkey_challenge_invalid` (not a live factor challenge of this guard for the identity, the binding's session and its
purpose), `invalid_credentials` (malformed, not verified, not one the challenge allowed, or not the identity's) or
`passkey_counter_regressed`, which the caller already holding the identity may see. It checks the origin, the relying
party id hash, user presence, user verification where the challenge required it, the signature and the challenge, and
the sign counter rule above, a counter that stays at zero included. `observed` is what this assertion's authenticator
data showed (user presence, user verification, backup eligibility and backup state; resistant to phishing; no key
protection), never what the ceremony asked for: under preferred user verification an authenticator that did not verify
the user is reported as unverified. It counts nothing and reports no failure: the factor's outcome is the further-factor
package's to limit and report.

A registration and a removal ask the bound `Contracts\PasskeyFactorGate`, synchronously, inside the transaction on the
storage connection that writes or deletes the passkey's row, before it does: a gate that throws refuses the change,
which rolls back whole, and its exception reaches the caller. The default, `Passkeys\NoPasskeyFactors`, associates
nothing and refuses nothing. When the factor package enables passkeys as a factor, its gate associates a new passkey in
that same change, confirmed by the registration's own observed properties, and `register()`'s `PasskeyRegistration`
carries the association in `factor`; a registration the factor package asked for on a session passes its binding to
`registrationOptions($identity, $userName, binding: $binding)`, and the gate gets it back. A credential registered by
another while the gate runs rolls the whole change back, the gate's work with it, and is answered `already_registered`.

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
use SineMacula\Laravel\Authentication\Listeners\RevokeSessionsOnPasskeyRemoval;

Event::listen(PasskeyRemoved::class, RevokeSessionsOnPasskeyRemoval::class);
```

It ends every session of the identity with `factor_removed`; to keep the current session signed in, call
`Auth::sessions()->credentialRemoved($identity, Auth::session())` yourself instead. With a factor package, a passkey it
associated as a factor is removed through `remove()` (its gate first), and the factor package then calls
`Auth::sessions()->factorRemoved()` (see [Sign-in factors](sessions.md#sign-in-factors)); register the listener
alongside it only if every passkey removal should end every session. See `docs/design/passkeys.md`.

## Writing a sign-in method

A sign-in method verifies input the client sends to your sign-in route and answers with the first factor it proves, or
why it does not; the session service does everything else (the application policy, the limits, activity, the principal,
a further factor, the session and the tokens). Use a method for input the package verifies, such as a password, a code
your application issued, or an identity provider's signed assertion the method checks itself. Use `start()` instead when
something outside the session service has already proven the identity, such as an SSO callback your identity provider's
package handles: `start()` runs the same checks after the proof, but no `Attempting`, attempt limit or timebox, since
nothing is guessed there. A method signed in through `signIn()` gets all three. `start()` refuses the machine credential
kinds (`api_key`, `client_credentials`) as the method with an `InvalidArgumentException`, even when the application
lists them: they authenticate requests and exchanges, never sessions.

```php
use Illuminate\Contracts\Hashing\Hasher;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
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

    public function authenticate(SignInRequest $request): FirstFactor|FailureReason
    {
        $badge    = $this->identifier($request->guard, $request->input());
        $pin      = $request->input()['pin'] ?? null;
        $identity = $badge === null ? null : $request->provider->retrieveByCredentials(['badge_number' => $badge]);

        if (! $identity instanceof Identity || ! is_string($pin) || ! $request->reserveAccountAttempt($identity)) {
            return FailureReason::INVALID_CREDENTIALS;
        }

        return $this->hasher->check($pin, $identity->pin_hash)
            ? new FirstFactor($identity, new Channel(ChannelKind::UNKNOWN, $badge), methods: ['pin'])
            : FailureReason::INVALID_CREDENTIALS;
    }
}
```

`identifierType()` names the identifier the method signs in by: the normaliser its limit counts it through, and the
identifier a guard that requires verified identifiers checks. Return `null` for a method that uses no identifier (an
assertion that names the identity itself): then only the IP address is limited and the verified-identifier requirement
does not apply. `identifier()` returns the identifier as the input gives it, for the limits and the failure events,
never to look anyone up. `authenticate()` returns a `Proofs\FirstFactor` (the identity, the channel it proved itself
over with its destination or credential reference of up to 255 characters, what was observed about the authenticator,
`null` for anything not observed, and the RFC 8176 `amr` values the proof stands for, here `pin`: at most 8, each 1 to
48 printable ASCII characters other than `"` and `\`, a private value namespaced like `urn:example:amr:badge`), or
`FailureReason::INVALID_CREDENTIALS` for anything the input did not prove. The session records it as its first proof,
and the access token's `amr` is derived from its values; `mfa` is reserved for an adapter's report of multifactor
authentication, and a `FirstFactor` that names it throws an `InvalidArgumentException`. The package's own methods report
`pwd` (password), `otp` (email code, and a code of any type registered with `extend()`), `sms` (phone code) and `pop`
(passkey). A method may also answer `identifier_unverified`, but only once its input proved possession of the identifier
(as a one-time code does), and `code_expired`, `code_exhausted`, `passkey_challenge_invalid` or
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
takes two slots. The slots belong to the sign-in: they are all given back once its session started, or its pending
sign-in's completion committed, and the guard is bound to it. A sign-in or a completion that your transaction rolls back
gives nothing back, since the pending sign-in it used comes back with the rollback and can be completed again. If giving
them back fails, the error is reported to your exception handler rather than thrown: the session already stands, and a
throw would stop the commit's later callbacks (another session's events, your own `DB::afterCommit()` work) from
running. The slots not given back stay counted.

The request's input holds the client's secrets, so it is read through `$request->input()` and kept in a private
`\SensitiveParameterValue`: no dump of the request, nor a trace that holds it, shows the password or code. Read what
the method needs from it, and never log it.

To unit-test a method, build its request yourself. `new SignInRequest('kiosk', $provider, $input, $client)` allows every
account check; a fifth argument decides them instead, so `fn (Identity $identity): bool => false` gives you a request
whose accounts have used up their attempts, to test the `invalid_credentials` answer.

Register the method under a lower-case name of its own (a letter, then letters, digits or underscores; `extend()`
refuses anything else, the package's own `password`, `phone_code`, `email_code` and `passkey`, and the machine
credential kinds `api_key` and `client_credentials`; see [Extensibility](extending.md#extensibility)), from a service
provider once the registry resolves (see [Binding order](extending.md#binding-order)), and allow that exact name in each
application's `application.methods`:

```php
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;

// In a service provider's register():
$this->callAfterResolving(SignInMethodManager::class, static function (SignInMethodManager $methods): void {
    $methods->extend('badge', fn ($app) => $app->make(BadgeSignIn::class));
});
```

```php
'kiosk' => [
    'driver'      => 'jwt',
    'provider'    => 'staff',
    'application' => ['methods' => ['badge']],
],
```

```php
$result = Auth::sessions('kiosk')->signIn('badge', $request->only('badge_number', 'pin'));
```

## Pending sessions

A sign-in that still has requirements left issues no token. Its session is written pending, with `status: pending`
and the requirements it waits on in `requires`, in the order they must be met: `mfa` (a further factor), then
`principal` (a choice of principal). The result `isPending()`; its `pending` is a `Sessions\PendingSession` (the
session's `id`, the guard, the identity, the principal and active tenant once one is selected, `requires`, the method,
`expiresAt`, the session record, the `requirement` its authentication still falls short of, its `firstFactor`, its
counting proofs through `proofs()`, and the `principals` to choose from while the choice comes first), and its
`credential` is the pending credential. Hand the client the id, `requires` and the credential in the response body,
never in a URL or a cookie:

```php
if ($result->isPending()) {
    return SecretResponse::json([
        'status'             => 'pending',
        'id'                 => $result->pending->id,
        'requires'           => array_map(fn ($requirement) => $requirement->value, $result->pending->requires),
        'pending_credential' => $result->credential,
    ]);
}
```

The session keeps its id from pending to active, and the id grants nothing. The credential, `<id>.<secret>`, is its
only key: only the digest of its secret is stored, it is not a JWT (so it authenticates no request and refreshes
nothing, and no token is ever accepted as one), it works only for this guard, and it expires
`session.pending_ttl_seconds` after it is issued (five minutes by default, never past the session's absolute deadline),
when the pending session has simply ended. It is a `Secret` here, as the token pair's tokens are, which
`SecretResponse::json()` reveals into the body (see [Secrets in responses](#secrets-in-responses)).

### In order

A sign-in follows one order whichever way it starts:

1. the credential is verified, and the identity checked (not a machine identity, active, and admitted with the
   identifier type the sign-in used);
2. the principals the identity may use the application as are found: its `principals()`, read on the write connection
   (the resolver's default for an identity that is its own principal), each active, in an active tenant and allowed to
   use the application. With none left the sign-in fails, after the credential was verified, with the reason the last
   one was left out for, or `principal_unresolved`: answer it 403;
3. the principal the context names, when it is among them (`principal_mismatch` otherwise), or the only one, is
   selected; with several and none named, a choice is outstanding;
4. the identity-level factor policy is asked, before any principal is chosen (see [Additional
   factors](#additional-factors));
5. a selected principal's active tenant is admitted: `SignInContext::$tenant`, or the principal's own;
6. that tenant's authentication policy is asked (see [Tenant authentication
   policies](sessions.md#tenant-authentication-policies)): one that requires a connection the sign-in was not
   established through refuses it as `sso_required`, writing nothing, and one that requires a further factor the
   sign-in lacks makes `mfa` outstanding.

With nothing outstanding the session starts active, as above, recording the version of the tenant policy's answer.
Otherwise it is written pending, with the first-factor proof and the provenance the active session will carry, and
`SessionPending` reports it once committed, with what it waits on and its expiry, never the credential. The sign-in's
attempt slots, the account's included, stay taken until the session first activates, and are given back then; a pending
session that is discarded or expires leaves them counted, so each guess at a further factor costs a sign-in attempt.
With the password method the guesses are bounded by the account's own count, whichever spelling of the identifier and
whichever guard each sign-in used, held to the most permissive `per_identifier` limit among the guards that check the
account (see [Rate limits](configuration.md#rate-limits)). A sign-in that `start()` began took no slots, since nothing
was guessed.

### Actions

A pending credential allows only the actions of the session's first outstanding requirement, by stable names
(`Sessions\Enums\PendingAction`):

| Requirement | Actions                                                                                                                 |
|-------------|-------------------------------------------------------------------------------------------------------------------------|
| `mfa`       | `mfa.list_factors`, `mfa.send_code`, `mfa.verify`, `mfa.start_bootstrap_enrollment`, `mfa.confirm_bootstrap_enrollment` |
| `principal` | `list_principals`, `choose_principal`                                                                                   |

So no principal is listed or chosen while a factor is outstanding, and nothing is allowed because of a route. The
`mfa.*` names follow the factor package's actions, spelt with this package's identifiers (`enrollment`), so the
integration between the two maps them by case rather than by value. Listing factors and enrolling one are the factor
package's calls, which check the credential here first with `pending()`:

```php
$pending = Auth::sessions('api')->pending($credential, PendingAction::VERIFY);

if ($pending === null) {
    abort(401); // unknown, expired, discarded, activated, another guard's, refused, or not allowed now
}
```

`pending($credential, $action)` reads only, dispatching nothing; it answers `null` for a credential that names no live
pending session of this guard, or whose session does not allow the action now (none given: any), and for a session that
can never activate because the gate would refuse its identity (a machine identity, an inactive one, or an identifier
type the application no longer admits), its method, or the principal and active tenant it records (the principal
inactive or refused by `ApplicationAccess`, its own tenant inactive, or the active tenant unresolvable, inactive or
refused by `TenantAccess`), so no code is sent and no enrolment begun for it. The tenant it describes is the one the
gate admitted. Whether a bootstrap enrolment applies (a factor is required and the identity has none) is the factor
package's to judge.

### Satisfying a further factor

The factor package verifies the factor for `$pending->identity` and hands its proof to `satisfy()`:

```php
$result = Auth::sessions('api')->satisfy($credential, $proof);
```

`$proof` is the `Proofs\ProofResult` the adapter verified: its kind (`additional_factor`, or `recovery_code` for the
fallback), method, channel and factor, what was observed, the adapter's `Evaluation` (accepted, and whether it amounts
to multifactor authentication), its `amr` values, when it was made, and its `ProofBinding` (the identity, the guard,
`$pending->id` as the session, and `Purpose::SIGN_IN`, or `Purpose::ENROLLMENT` for the factor that confirms a
bootstrap enrolment). It is refused as `proof_invalid` when it is any other kind (a reauthentication, external or not,
never counts), made for another purpose, not accepted, or made after now or before the session began waiting, and as
`proof_binding_mismatch` when it names another identity, guard or session; `pending_action_not_allowed` when the factor
is not the first requirement.

Under the session's row lock, the session is checked again (the identity, the method still allowed, and the principal
and tenant it records, if any), the proof is stored with its other proofs, and what it waits on is judged again, the
tenant's authentication policy included (its further factor is met only as the bound `RequirementCheck` judges the
stored proofs, and one that requires a connection refuses the call as `sso_required`, storing nothing): with nothing
left it activates in place (the guard is bound, the pair issued, the credential consumed, `SessionCreated` and
`SignedIn` reported, the slots given back), with the choice left it moves on to it (the result is pending again, with no
new credential and the principals listed), and otherwise it stays pending. The access token's `amr` carries the proof's
values, and `mfa` when its evaluation reports multifactor authentication. A refusal stores nothing and never revokes the
session, which waits until its credential expires; every refusal reports `Failed` and `AuthenticationFailed`, and a
credential that names nothing is `pending_invalid`.

### Choosing a principal

```php
$result = Auth::sessions('api')->choose($credential, $principal, TenantSelection::principalDefault());
```

`choose()` takes one of `$pending->principals` (also listed by `Auth::sessions('api')->principals($identity,
$identifierType)`, and got by its id with `principal($identity, $principalId, $identifierType)`), and the tenant it is
to be active in (the principal's own unless one is given). Under the row lock the identity and method are checked again,
the principal must be the identity's, resolved through the hinted path as the very one named (`principal_mismatch`), and
allowed to use the application, and the tenant one it may act in and active. The chosen tenant's authentication policy
is asked next: one that requires a connection refuses this principal as `sso_required`, leaving the session pending for
another choice. The identity-level factor policy is then asked again: a further factor it or the tenant now asks for
records the principal and tenant and leaves the session waiting for it, with the same credential; otherwise the session
activates as the principal. A refused choice leaves the session pending for another; `pending_action_not_allowed` while
a factor is outstanding.

### Discarding

`discard($credential)` ends a pending session (a factor that failed, a choice abandoned): it is revoked as `signed_out`
and `SessionRevoked` reports it, so its credential works no more. It returns whether the credential named a live pending
session of this guard. Revoking an identity's sessions, signing out everywhere and pruning reach pending sessions too:
they are sessions like any other.

### The session it activates

The session that activates is the pending one: same id, the first factor's proof and the provenance it was written with,
and the further factor `satisfy()` stored. On a sign-in's first activation the session the client proved it holds (with
its refresh token in the context) is revoked as `superseded`, reported before `SessionCreated`, but only while it still
holds the refresh token it was proven with, records the same owner, guard and principal, and is active and not revoked.
When it changed, the session is judged again without it, the additional-factor policy included: it activates and
supersedes nothing, or stays pending on a further factor the policy now asks for without the proven session's trust. A
pending session is never listed, and no access or refresh token of it is accepted (`session_pending`) until it
activates.

## Additional factors

The additional-factor policy (`Contracts\AdditionalFactorPolicy`, by default one that asks for nothing; an MFA package
or the application binds its own) is asked about the identity, after its first factor is verified and before any
principal is chosen, with the application, the identity, the first factor's whole proof, the client and the session the
client proved it holds, if any; it names no principal or tenant (a tenant that asks more does so through its tenant
authentication policy). It answers a `Requirements\Requirement`: what the session's authentication must include beyond
its first factor. The bound `Contracts\RequirementCheck` judges whether the session's proofs meet it; the default check
meets nothing, so a requirement no factor package judges keeps the session pending. At sign-in the check judges the
first factor alone, so a requirement it meets (a minimum assurance level the sign-in already reaches, say) starts the
session active. Otherwise the session is pending with `mfa` outstanding, and its `PendingSession::$requirement` names
what it still falls short of. The policy is asked again, and the check judges again, each time the pending session is
acted on, when a refresh or a switch returns the session to pending under its tenant's authentication policy (not when
that policy is met), and when `factorRemoved()` judges the current session again. `attempt()`, which cannot wait,
refuses as `additional_factor_required` a sign-in whose password alone does not meet the requirement.

## Enumeration resistance

No response, and no response time, tells a client whether an identifier belongs to anyone. Routes and responses are
yours; what the package guarantees for each method and helper, and what its tests hold it to, is:

| Flow                      | Same outcome for an unknown identifier                                                                                                                                                              | Delivery                                          | Timing                                                                                                       |
|---------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------|--------------------------------------------------------------------------------------------------------------|
| Password sign-in          | `invalid_credentials` for an unknown identifier, a wrong password and a locked account                                                                                                              | None                                              | Padded to the credential timebox                                                                             |
| Code request              | A code is issued for any identifier: same status, a challenge id, expiry, cooldown, delivery cap, limits and statements                                                                             | Queued job (after the response on `sync`)         | No identity work at all, so nothing to pad                                                                   |
| Code sign-in              | `invalid_credentials` for an unknown identifier, a wrong, expired, exhausted or used code, another challenge, and a locked account                                                                  | None                                              | Padded to the credential timebox                                                                             |
| Verification by code      | Not applicable: the caller holds the identity                                                                                                                                                       | Queued job (after the response on `sync`)         | Not applicable                                                                                               |
| Reset request             | A token or code is issued for any identifier: same status, a code's challenge id, expiry, cooldown, delivery cap, limits and statements                                                             | Queued job (after the response on `sync`)         | No identity work at all, so nothing to pad                                                                   |
| Reset submission          | `invalid` for an unknown identifier and for a wrong, expired, exhausted, used or ineligible proof (an inactive, machine or unverified holder); the policy's verdict does not depend on the identity | None                                              | Padded to the credential timebox; a held address adds only the lock of its row                               |
| Identifier change request | Not applicable: the caller holds the identity; the answer never depends on whether another identity holds the new identifier                                                                        | Queued job for a code; a link is returned to send | Not applicable                                                                                               |
| Passkey sign-in           | No identifier to probe: an unknown, foreign or ownerless passkey, a bad signature or user handle, a regressed counter and a locked account all answer `invalid_credentials`                         | None                                              | Padded to the credential timebox, owner looked up or not; sign-in options do no identity work                |
| API key                   | `credential_invalid` for a malformed key, an unknown public part and a wrong secret; the key's status only once the secret verifies                                                                 | None                                              | No hasher; an unknown public part is checked against a dummy digest, so the work and statements are the same |
| Client credentials        | 401 `invalid_client` with the same body for every client failure (a Basic challenge only to a Basic client); `slow_down` counts the client id as given, when limited                                | None                                              | As API key                                                                                                   |

The code request's answer for a number nobody has is `sent`, with the same expiry as any other; only the delivery job
looks the number up, and it sends nothing to an unknown, unverified, inactive or machine identity, or to one that holds
only a look-alike of it. Answer `sent` the same way whatever happens next, and do not tell the client whether a message
went out.
