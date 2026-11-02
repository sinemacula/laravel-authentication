# Refreshing

Refresh through the guard's session service, with the token the request carries, read through the guard's refresh
token transport:

```php
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;

$result = Auth::sessions('api')->refreshFromRequest();

abort_if($result === null, 401); // no refresh token in the request, and nothing was dispatched

if ($result->isFailed()) {
    // Failed and AuthenticationFailed were dispatched (flow refresh); $result->reason says why.
    if ($result->reason === FailureReason::RATE_LIMITED) {
        throw new ThrottleRequestsException(__('Too Many Attempts.'), null, ['Retry-After' => $result->retryAfter]);
    }

    abort(401);
}

if ($result->isPending()) {
    // The session's tenant now asks for a further factor: no pair, only a pending credential.
    return SecretResponse::json(['pending_credential' => $result->credential, 'requires' => ['mfa']]);
}

return SecretResponse::json([
    'access_token'  => $result->session->tokens->accessToken,
    'refresh_token' => $result->session->tokens->refreshToken,
]);
```

A refresh rotates the session's refresh token and binds the guard to the refreshed session for the rest of the request.
The result's `session` is that session: its `identity`, `principal`, `record` (the session row to set a refresh cookie
for), the `method` its sign-in used, and the new pair in `tokens`, whose tokens are secrets `SecretResponse::json()`
reveals into a body that is never stored (see [Secrets in responses](signing-in.md#secrets-in-responses)). Every refusal
is returned, never thrown, with its `reason`; `rate_limited` also carries the seconds to wait in `retryAfter`, which the
route answers with a 429 and `Retry-After` so the client waits. A refresh that finds the session's tenant now asking for
a further factor the session lacks returns it to pending instead: `isPending()`, with `pending` and `credential` and no
`session`, until the factor is satisfied (see [Tenant authentication
policies](sessions.md#tenant-authentication-policies)).

Each application's refresh token travels one way, its `refresh_token.transport`: `body` (the default) reads it from
the `refresh_token` field of the JSON or form body (never the query string) or the `X-Refresh-Token` header (`header`
set to `null` reads the body field only), and hands it back in the pair; `cookie` reads it only from the application's
`HttpOnly` cookie and hands back the cookie instead (see [Refresh token cookie](#refresh-token-cookie)). Every request
is read in all three carriers, whatever the transport. A request that carries a token in more than one of them, or the
cookie twice, equal or not, is refused as `refresh_token_conflict`: the server never chooses between two tokens, and a
request cannot get past the cookie's cross-site checks by also sending the token another way. A request that carries
it only in a carrier that is not the application's transport (the cookie to a body application, the body or a header
to a cookie application) is refused as `refresh_transport_mismatch`. A value that is not one non-empty string is
`token_invalid`. A refusal by the transport dispatches `Attempting`, `Failed` and `AuthenticationFailed` (flow
`refresh`) like any failed refresh, without touching a session or counting against a limit; a token the exchange
refuses fails with the exchange's reason, `rate_limited` included. The result's `source` (`RefreshTokenSource::COOKIE`,
`BODY` or `HEADER`) says where the token came from. `Auth::refreshTransport('api')->read($request)` reads a request the
same way without refreshing.

The package defaults are `authentication.refresh_token`; a guard overrides any of them in a `refresh_token` block on its
`config/auth.php` entry, where a key it sets wins, inside `cookie` too:

```php
'api' => [
    'driver'        => 'jwt',
    'provider'      => 'users',
    'application'   => ['methods' => ['password']],
    'refresh_token' => ['header' => 'X-App-Refresh'],
],
```

A malformed value or an unknown key fails closed with an `InvalidArgumentException` naming the guard and the key, read
when a sign-in, refresh or switch reads the transport, and `authentication:check` reports it.
`Auth::sessions('api')->refresh($refreshToken)` refreshes a body application with a token your code reads itself and
answers the same `RefreshResult`, without a `source`. A cookie application's token is read only from its cookie, with
the cookie's cross-site checks, so on a cookie application `refresh($refreshToken)` (and `switchTo()` and
`signOutWith()`) throws a `LogicException`: use `refreshFromRequest()`. The `me` route binding reads a route's refresh
credential through the same transport (see [The `me` route binding](sessions.md#the-me-route-binding)).

A refresh is held to the guard as well as the token. A session the row records for another guard (or for none) fails
with `session_guard_mismatch` and is left alone, even for a token that would be a replay, and a bearer token naming it
is rejected as if the session were missing. The application policy is asked again on every refresh: the method that
started the session (the session's `sign_in_method`) must still be one the guard allows (`method_not_allowed`; a session
that records none fails too), and the policy must still admit the owner as the principal (`principal_ineligible`).
Neither revokes the session, so the session refreshes again once the policy allows it. Each rotation moves the idle
deadline by the idle lifetime the policy gives the guard, never past the session's absolute deadline, and never moves
the absolute deadline: a session capped at its sign-in's own deadline stays capped, and one with no absolute deadline
(an application that sets no absolute limit) gets none from a refresh. The new refresh token, and the cookie that
carries it, expire at the session's end, its idle deadline alone when it has no absolute one.

A refresh token is accepted only for the principal its session records. After a switch of principal (see [Switching
principal or tenant](sessions.md#switching-principal-or-tenant)), the refresh token of the principal switched from fails
with `session_principal_mismatch`, even inside the grace window, and the session is left alone; a token presented after
the grace window is a replay, as any rotated token is. A refresh that loses its write to a switch is judged the same
way: when the switch moved the session to another principal it fails as `session_principal_mismatch`, and when it moved
it to another tenant as `session_tenant_mismatch`, so no pair is ever issued for a context the refresh did not judge. A
refresh keeps the session in its active tenant, and is refused once the tenant is no longer one `TenantAccess` lets the
principal act in (`tenant_ineligible`) or is inactive (`tenant_inactive`).

Failed refreshes are counted against the token's session and the request's IP address by the bound `AttemptLimiter`;
successful ones are not. Once either count is full, a refresh dispatches `Failed` and `AuthenticationFailed`
(`rate_limited`) without looking the session up, and returns `rate_limited` with the seconds until the full count's
window ends in `retryAfter`; answer it with Laravel's `ThrottleRequestsException`, as above, which renders as a 429 with
`Retry-After`.

A failure before the stored rotation commits, such as an error while signing the new pair, leaves the presented refresh
token valid for a retry. Once the rotation is written, the refresh schedules `Refreshed` for its commit on the session's
connection (dispatched at once outside a transaction, after your transaction commits inside one, and never when it is
rolled back) before it binds the new context, so a listener that throws on a bind event cannot keep `Refreshed` from
being reported; an exception from a listener on any of those events still loses the new pair, but a retry with the
presented token inside the grace window still gets the current credential (see [Refresh token
replay](#refresh-token-replay)). Keep those listeners from throwing or queue them, so a retry is never needed.

## Moving from the guard's refresh

The guard no longer refreshes: `refresh()` and `refreshFromRequest()` moved to the session service, beside switching
principal and signing out, and return every refusal instead of throwing the 429.

```php
// Before
$result = auth()->guard('api')->refreshFromRequest(); // FailureReason|Jwt\RefreshResult|null, 429 thrown
$result = auth()->guard('api')->refresh($token);      // ?Jwt\RefreshResult, null for any refusal
$result->accessToken; $result->refreshToken; $result->source;

// After
$result = Auth::sessions('api')->refreshFromRequest(); // ?Sessions\RefreshResult, null: no token in the request
$result = Auth::sessions('api')->refresh($token);      // Sessions\RefreshResult
$result->session->tokens->accessToken; $result->session->tokens->refreshToken; $result->source;
$result->session->record;                              // the session, without reading the guard
```

A check written for the old shape can now be wrong without failing: `$result !== null` and `if ($result)` hold for a
refused refresh too, `$result instanceof FailureReason` never holds, and neither does an `instanceof` check against
`Jwt\RefreshResult`, which is now the bare token pair `Jwt\TokenPair`, with no `source`. Ask `isRefreshed()` or
`isFailed()` and read `reason`. A route that let the guard's 429 render itself now answers `rate_limited` itself, as the
example above does.

## Refresh token cookie

A browser application can keep its refresh token where its scripts cannot read it, in an `HttpOnly` cookie the API
sets on its own responses. The token lives only in the browser; nothing is stored on the server, so the API stays
stateless. Give the application the `cookie` transport and the path its routes live under:

```php
'browser' => [
    'driver'        => 'jwt',
    'provider'      => 'users',
    'application'   => ['methods' => ['password']],
    'refresh_token' => [
        'transport' => 'cookie',
        'cookie'    => ['path' => '/auth'],
    ],
],
```

A cookie application never hands its code the plain refresh token: the pair of every sign-in, `start()`, activation
(`satisfy()`, `choose()`), refresh and switch carries `refreshToken` as `null` and `refreshCookie`, a
`Http\RefreshCookie` that holds the token as a `Secret` with the cookie's name, path and expiry. Attach it to the
response with `attachTo()`, which also marks the response `Cache-Control: no-store`; `cookie()` makes the Symfony
`Cookie` itself, revealing the token into it, for a response you build some other way. A body application's pair
carries the token and no cookie. The pending credential of a pending sign-in is never a cookie: it travels in the body
for every application.

Put the routes that read the cookie under that path (refresh, a switch, see
[Switching principal or tenant](sessions.md#switching-principal-or-tenant), and sign-in for a browser that proves its
session), and attach the cookie whenever the API hands out a pair:

```php
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;

Route::post('/auth/sign-in', function (Request $request) {
    $transport = Auth::refreshTransport('browser');

    abort_unless($transport->isSameSiteRequest($request), 403);

    // A browser that still holds a refresh cookie proves its session, which the sign-in then replaces.
    $presented = $transport->read($request);
    $context   = SignInContext::fromRequest($request, refreshToken: $presented instanceof PresentedRefreshToken ? $presented->token : null);
    $tokens    = Auth::sessions('browser')->signIn('password', $request->only('email', 'password'), $context)->session?->tokens;

    abort_if($tokens === null, 401);

    return $tokens->refreshCookie->attachTo(SecretResponse::json(['access_token' => $tokens->accessToken]));
});

Route::post('/auth/refresh', function () {
    $result = Auth::sessions('browser')->refreshFromRequest();

    if ($result?->reason === FailureReason::RATE_LIMITED) {
        throw new ThrottleRequestsException(__('Too Many Attempts.'), null, ['Retry-After' => $result->retryAfter]);
    }

    abort_if($result?->session === null, 401);

    $tokens = $result->session->tokens;

    return $tokens->refreshCookie->attachTo(SecretResponse::json(['access_token' => $tokens->accessToken]));
});
```

Signing out clears the cookie (see [Signing out and revoking sessions](sessions.md#signing-out-and-revoking-sessions)).

The cookie is `HttpOnly`, `Secure` and `SameSite=Strict`, host-only (it never names a `Domain`), scoped to the
configured `path`, and expires when the session does, as the refresh token in it does. Its name is the application's
own unless `cookie.name` sets one: `__Host-<guard>_refresh_token` for a cookie application whose path is `/`,
otherwise `__Secure-<guard>_refresh_token` (`__Secure-browser_refresh_token` above), so two browser applications on one
host never overwrite each other's cookie, whatever their paths. A cookie application whose guard name makes no cookie
name (one with a space or a separator, say) fails closed until `cookie.name` is set; a body application with such a name
needs nothing, and looks for no cookie of its own. Two cookie applications with the same name fail closed, naming both
guards. `forgetCookie()` returns the same cookie already expired; any route may send it, a logout
route outside the cookie's path included, since a path limits where the browser sends a cookie, not which response
may set it. A `__Host-` name set for a cookie application is accepted only with the path `/`, as browsers require; a
body application never sets the cookie, so a package-wide `__Host-` name does not bind it. Clearing the cookie of a
body application throws a `LogicException`. Names PHP renames when it parses a request are refused, as the token would
never be found under them: a `.` in the cookie or a header name, and a `.`, a space or a bracket in `body_field`.

"The cookie, the application and the session agree" holds on every refresh and switch: the cookie read is the
application's own name, unique among cookie applications; it is the application's transport
(`refresh_transport_mismatch` otherwise); the token's `client_id` is the application (`token_invalid` otherwise, so a
token another application issued fails even in this one's cookie); the session it names is the application's
(`session_guard_mismatch`, without touching that session); and the cookie a result sets is that application's.

A browser attaches the cookie by itself, to any request for its path, so a refresh read from it is held to two checks a
cross-site page cannot pass: its `Origin` must be the API's own (the request's scheme and host) or one of
`cookie.allowed_origins` (each exactly `scheme://host[:port]`), and it must carry the `cookie.csrf_header` header
(`X-Requested-With` by default) with a value, which a form or a simple request cannot send; a header a browser sends on
its own (`Content-Type`, `Origin`, any `Sec-` header and the like, also when spelt with `_` for `-`) is refused as the
`csrf_header`. Anything else is `cross_site_request`. A route that sets the cookie must hold its request to the same
checks, the sign-in above all: a cross-site page can auto-submit a form to it with an attacker's credentials, and a
browser keeps a `SameSite=Strict` cookie set by the response to such a top-level navigation, so without the check the
victim's browser would hold the attacker's refresh cookie and its own scripts would then pass the refresh checks inside
the attacker's account. The package cannot make that check for you, since the callback of an external provider's sign-in
(`start()`) arrives as just such a cross-site navigation;
`Auth::refreshTransport('browser')->isSameSiteRequest($request)` is the check, as the sign-in route above uses it. A
script refreshes with:

```js
await fetch('/auth/refresh', {method: 'POST', credentials: 'include', headers: {'X-Requested-With': 'fetch'}});
```

Another host of the same site, such as a marketing site, a subdomain serving user content or one taken over, can plant
a cookie of the same name: a `__Secure-` cookie may name the parent `Domain`, and a browser sends one with a longer
`Path` before the API's own. PHP keeps only the first cookie of a name, so a request that carries the refresh cookie
twice (counted under the name PHP files each one under) is refused as `refresh_token_conflict`, and the server never
refreshes with the planted one. The planted cookie still fails every refresh until it expires, though, and the API
cannot clear it, since `forgetCookie()` names the API's own host and path, not the planter's; and a browser that holds
no refresh cookie of its own would send the planted one alone. If you do not trust every host of the site, give the
application the path `/`, so its name is `__Host-<guard>_refresh_token`: a browser keeps a `__Host-` cookie only from
the API's own host, with no `Domain`, so no other host can plant one. The cost is that the cookie then rides on every
request to the API's host, not only the routes that read it; no other application on the host reads it, since its
name is not theirs.

`SameSite=Strict` keeps the cookie from being sent from another site at all, so `allowed_origins` serves origins of
the same site, such as an application on `app.example.com` calling an API on `api.example.com`. For such an origin,
let Laravel's CORS middleware allow credentials only for the origins you list (`supports_credentials` set to `true`
and `allowed_origins` naming them in `config/cors.php`, never `*`). Behind a proxy or load balancer that ends TLS,
configure Laravel's trusted proxies, so the request knows its own scheme and host and the API's own origin matches.

Laravel's `EncryptCookies` middleware, when it runs on these routes, encrypts the cookies a response sets and decrypts
the ones a request sends. The refresh token is already signed, and only the API reads it, so the simplest setup leaves
it out:

```php
->withMiddleware(function (Middleware $middleware) {
    $middleware->encryptCookies(except: ['__Secure-browser_refresh_token']);
})
```

If you keep it encrypted, set and read the cookie on routes that both run `EncryptCookies`, so the value the browser
returns is the one the middleware made; a value it cannot decrypt reaches the guard as an invalid token
(`token_invalid`), and the client signs in again. Routes in `routes/api.php` do not run `EncryptCookies` unless you
add it.

## Refresh token replay

Refresh tokens stay signed JWTs, and each one carries the session's rotation id, which the session stores only as a
SHA-256 digest. Every successful refresh rotates the session to the next rotation id and remembers the one it replaced,
with the time of the rotation. A validly signed refresh token for a live session then carries one of three ids:

- the current one: the refresh rotates it and returns a new pair;
- the one the current one replaced, presented within `refresh_grace_seconds` (30 by default) of that rotation: the
  refresh returns a new pair carrying the session's current rotation id, and writes no rotation state, so a client that
  lost the response, or a second tab that refreshed at the same moment, keeps its session, and retries never extend the
  window;
- any other id: the token was rotated before, so it has been replayed, perhaps stolen. The session is revoked at once
  (`revoked_at` and `revoked_reason = rotation_reuse`, both digests cleared), `SessionRevoked` and
  `AuthenticationFailed` (`rotation_reuse`) are dispatched, and every token of the session stops working, access tokens
  included.

Only the immediately previous id is honoured: after two quick refreshes, a delayed retry of the first token is a
replay. With `refresh_grace_seconds` set to 0 the previous id is a replay too. A session that holds no refresh
credential cannot tell a replay from anything else, so its tokens fail with `refresh_key_missing` and the session is
left alone. When a parallel refresh changes the session between this refresh's read and its write, the row is judged
again as it now is: usually that makes this refresh a grace retry; a deadline that moved in between fails it with
`rotation_conflict`, without revoking anything, and the client can simply retry. So does a refresh that found the
session short of its tenant's policy and lost its revocation or return to pending to another request: the policy it
asked refused a pair, so it gets none, and a revocation never applies to a session another request moved on (a switch
to a tenant it meets, say), whose next refresh is judged afresh.

A refresh token for a rotation id the session never held is a replay too. A client that signs in again with its current
refresh token (see [Signing in](signing-in.md#signing-in-the-session-service)) gets a new session, and its previous
session is revoked as `superseded`: that session's refresh tokens are then refused as `session_revoked`, not judged as
replays, so they cannot touch the new session. A client that loses the sign-in response and retries with the old token
proves nothing (its session is already revoked) and gets another new session; the one whose response was lost lingers
unused until it expires or is pruned. Do not give an existing session a new `refresh_key` yourself; let the session
service do it.

Every refresh judges the session at one moment, taken when it starts, so application servers should keep synchronised
clocks. The package opens no transaction. If you call `refresh()` inside your own transaction, do not roll it back after
a failed refresh: a rollback also undoes a replay revocation. `SessionRevoked` is dispatched once the revocation is
committed on the session's own connection: at once outside a transaction, so before `Failed` and `AuthenticationFailed`,
and after the commit inside one, so after them; a rolled-back revocation is never reported, and a transaction on another
connection neither delays nor withdraws it. The transaction that Laravel's `DatabaseTransactions` and `RefreshDatabase`
testing traits wrap around each test does not count either, so a test sees `SessionRevoked` when the application would.
Under PostgreSQL's REPEATABLE READ, a parallel refresh that commits first makes this one fail with a serialization
error, which surfaces as a server error for you to retry.
