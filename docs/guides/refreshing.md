# Refreshing

Refresh with the token the request carries, read through the guard's refresh token transport:

```php
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;

$result = auth()->guard('api')->refreshFromRequest();

if (!$result instanceof RefreshResult) {
    // null: the request carried no refresh token, and nothing was dispatched.
    // A FailureReason: refused, after Failed and AuthenticationFailed with that reason.
    abort(401);
}

return [
    'access_token'  => $result->accessToken,
    'refresh_token' => $result->refreshToken,
];
```

The guard reads the token only from the sources its `refresh_token` settings list: `body` and `header` by default, the
`refresh_token` field of the JSON or form body (never the query string) and the `X-Refresh-Token` header, or the
`cookie` (see [Refresh token cookie](#refresh-token-cookie)). A request that carries a token in more than one of them,
equal or not, is refused as `refresh_token_conflict`: the server never chooses between two tokens, and a request cannot
get past the cookie's cross-site checks by also sending the token another way. A value that is not one non-empty string
is `token_invalid`. A refusal by the transport dispatches `Attempting`, `Failed` and `AuthenticationFailed` (flow
`refresh`) like any failed refresh, without touching a device or counting against a limit; a token the exchange refuses
fails with the exchange's reason, the 429 for `rate_limited` included. The result's `source`
(`RefreshTokenSource::COOKIE`, `BODY` or `HEADER`) says where the token came from, so a refresh read from the cookie can
be answered with a cookie. `Auth::refreshTransport('api')->read($request)` reads a request the same way without
refreshing.

The package defaults are `authentication.refresh_token`; a guard overrides any of them in a `refresh_token` block on its
`config/auth.php` entry, where a key it sets wins, inside `cookie` too:

```php
'api' => [
    'driver'        => 'jwt',
    'provider'      => 'users',
    'refresh_token' => ['sources' => ['header'], 'header' => 'X-App-Refresh'],
],
```

A malformed value or an unknown key fails closed with an `InvalidArgumentException` naming the guard and the key, read
when the guard reads a token. `refresh($refreshToken)` remains for a token your code reads itself and returns the
result or `null`; never pass it a token read from the refresh cookie, which only `refreshFromRequest()` reads with the
cookie's cross-site checks.

A refresh is held to the guard as well as the token. A device the row records for another guard (or for none) fails
with `device_guard_mismatch` and is left alone, even for a token that would be a replay, and a bearer token naming it
is rejected as if the device were missing. The guard's audience policy is asked again on every refresh: the method that
started the session (the device's `sign_in_method`) must still be one the guard allows (`method_not_allowed`; a device
that records none fails too), and the policy must still admit the owner as the principal (`principal_ineligible`).
Neither revokes the device, so the session refreshes again once the policy allows it. Each rotation moves the idle
deadline by the idle lifetime the policy gives the principal's type.

A refresh token is accepted only for the principal its device records. After a switch (see [Switching
principal](sessions.md#switching-principal)), the refresh token of the principal switched from fails with
`device_principal_mismatch`, even inside the grace window, and the device is left alone; a token presented after the
grace window is a replay, as any rotated token is. A refresh that loses its write to a switch is judged the same way.

Failed refreshes are counted against the token's device and the request's IP address by the bound `AttemptLimiter`;
successful ones are not. Once either count is full, a refresh dispatches `Failed` and `AuthenticationFailed`
(`rate_limited`) without looking the device up, then throws Laravel's `ThrottleRequestsException`, which renders as a
429 with `Retry-After`.

A failure before the stored rotation commits, such as an error while signing the new pair, leaves the presented refresh
token valid for a retry. After the commit, the refresh binds the new context and dispatches `Refreshed` once the
rotation is committed on the device's connection; an exception from a listener on those events loses the new pair, but a
retry with the presented token inside the grace window still gets the current credential (see [Refresh token
replay](#refresh-token-replay)). Keep those listeners from throwing or queue them, so a retry is never needed.

## Refresh token cookie

A browser application can keep its refresh token where its scripts cannot read it, in an `HttpOnly` cookie the API
sets on its own responses. The token lives only in the browser; nothing is stored on the server, so the API stays
stateless. List the cookie as the guard's source and give it the path its routes live under:

```php
'browser' => [
    'driver'        => 'jwt',
    'provider'      => 'users',
    'refresh_token' => [
        'sources' => ['cookie'],
        'cookie'  => ['path' => '/auth'],
    ],
],
```

Put the routes that read the cookie under that path (refresh, a switch of principal, see
[Switching principal](sessions.md#switching-principal), and sign-in for a browser that proves its device), and set the
cookie with the guard's transport whenever the API hands out a pair:

```php
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;

Route::post('/auth/sign-in', function (Request $request) {
    $transport = Auth::refreshTransport('browser');

    abort_unless($transport->isSameSiteRequest($request), 403);

    // A browser that still holds a refresh cookie proves its device, which the sign-in then continues.
    $presented = $transport->read($request);
    $context   = SignInContext::fromRequest($request, refreshToken: $presented instanceof PresentedRefreshToken ? $presented->token : null);
    $session   = Auth::sessions('browser')->signIn('password', $request->only('email', 'password'), $context)->session;

    abort_if($session === null, 401);

    return response()->json(['access_token' => $session->tokens->accessToken])
        ->withCookie($transport->cookie($session->tokens->refreshToken, $session->device));
});

Route::post('/auth/refresh', function () {
    $guard  = Auth::guard('browser');
    $result = $guard->refreshFromRequest();

    abort_unless($result instanceof RefreshResult && $result->source === RefreshTokenSource::COOKIE, 401);

    return response()->json(['access_token' => $result->accessToken])
        ->withCookie(Auth::refreshTransport('browser')->cookie($result->refreshToken, $guard->device()));
});

Route::post('/logout', function () {
    Auth::guard('browser')->logout();

    return response()->noContent()->withCookie(Auth::refreshTransport('browser')->forgetCookie());
});
```

The cookie is `HttpOnly`, `Secure` and `SameSite=Strict`, named `__Secure-refresh_token` by default, scoped to the
configured `path` and `domain` (`null`, the default, keeps it to the API's host), and expires when the device's session
does, as the refresh token in it does. `forgetCookie()` returns the same cookie already expired; any route may send it,
a logout route outside the cookie's path included, since a path limits where the browser sends a cookie, not which
response may set it. On a guard that reads the cookie, a `__Host-` name is accepted only with the path `/` and no
domain, as browsers require; a guard that reads only the body or a header never sets the cookie, so a package-wide
`__Host-` name does not bind it. Setting or clearing the cookie on a guard that does not list `cookie` throws a
`LogicException`. Names PHP renames when it parses a request are refused, as the token would never be found under
them: a `.` in the cookie or a header name, and a `.`, a space or a bracket in `body_field`.

A browser attaches the cookie by itself, to any request for its path, so a refresh read from it is held to two checks a
cross-site page cannot pass: its `Origin` must be the API's own (the request's scheme and host) or one of
`cookie.allowed_origins` (each exactly `scheme://host[:port]`), and it must carry the `cookie.csrf_header` header
(`X-Requested-With` by default) with a value, which a form or a simple request cannot send; a header a browser sends on
its own (`Content-Type`, `Origin`, any `Sec-` header and the like, also when spelled with `_` for `-`) is refused as the
`csrf_header`. Anything else is `cross_site_request`. A route that sets the cookie must hold its request to the same
checks, the sign-in above all: a cross-site page can auto-submit a form to it with an attacker's credentials, and a
browser keeps a `SameSite=Strict` cookie set by the response to such a top-level navigation, so without the check the
victim's browser would hold the attacker's refresh cookie and its own scripts would then pass the refresh checks inside
the attacker's account. `Auth::refreshTransport('browser')->isSameSiteRequest($request)` is that check, as the sign-in
route above uses it. A script refreshes with:

```js
await fetch('/auth/refresh', {method: 'POST', credentials: 'include', headers: {'X-Requested-With': 'fetch'}});
```

Another host of the same site, such as a marketing site, a subdomain serving user content or one taken over, can plant
a cookie of the same name: a `__Secure-` cookie may name the parent `Domain`, and a browser sends one with a longer
`Path` before the API's own. PHP keeps only the first cookie of a name, so a request that carries the refresh cookie
twice (counted under the name PHP files each one under) is refused as `refresh_token_conflict`, and the server never
refreshes with the planted one. The planted cookie still fails every refresh until it expires, though, and the API
cannot clear it, since `forgetCookie()` names the guard's own domain and path, not the planter's; and a browser that
holds no refresh cookie of its own would send the planted one alone. If you do not trust every host of the site, name
the cookie `__Host-refresh_token` with the path `/`: a browser keeps a `__Host-` cookie only from the API's own host,
with no `Domain`, so no other host can plant one. The cost is that the cookie then rides on every request to the API's
host, not only the routes that read it.

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
    $middleware->encryptCookies(except: ['__Secure-refresh_token']);
})
```

If you keep it encrypted, set and read the cookie on routes that both run `EncryptCookies`, so the value the browser
returns is the one the middleware made; a value it cannot decrypt reaches the guard as an invalid token
(`token_invalid`), and the client signs in again. Routes in `routes/api.php` do not run `EncryptCookies` unless you
add it.

## Refresh token replay

Refresh tokens stay signed JWTs, and each one carries the device's rotation id, which the device stores only as a
SHA-256 digest. Every successful refresh rotates the device to the next rotation id and remembers the one it replaced,
with the time of the rotation. A validly signed refresh token for a live device then carries one of three ids:

- the current one: the refresh rotates it and returns a new pair;
- the one the current one replaced, presented within `refresh_grace_seconds` (30 by default) of that rotation: the
  refresh returns a new pair carrying the device's current rotation id, and writes no rotation state, so a client that
  lost the response, or a second tab that refreshed at the same moment, keeps its session, and retries never extend the
  window;
- any other id: the token was rotated before, so it has been replayed, perhaps stolen. The device is revoked at once
  (`revoked_at` and `revoked_reason = rotation_reuse`, both digests cleared), `DeviceRevoked` and `AuthenticationFailed`
  (`rotation_reuse`) are dispatched, and every token of the device stops working, access tokens included.

Only the immediately previous id is honoured: after two quick refreshes, a delayed retry of the first token is a
replay. With `refresh_grace_seconds` set to 0 the previous id is a replay too. A device that holds no refresh
credential cannot tell a replay from anything else, so its tokens fail with `refresh_key_missing` and the device is
left alone. When a parallel refresh changes the device between this refresh's read and its write, the row is judged
again as it now is: usually that makes this refresh a grace retry; a deadline that moved in between fails it with
`rotation_conflict`, without revoking anything, and the client can simply retry.

A refresh token for a rotation id the device never held is a replay too, and that includes a token from an earlier
session of the same device. A client that signs in again on its device (see
[Signing in](signing-in.md#signing-in-the-session-service)) starts a new session with a new rotation id, so the refresh
tokens of its earlier session become replays: presenting one while the new session is live revokes the device. The
client that proved the device with its current refresh token has just received the replacement; a client that loses the
sign-in response and retries with the old token proves nothing, gets a new device, and leaves the old one to be revoked
if that token is ever presented again. Restarting the deadlines cannot revive an access token: its `exp` was capped at
the end of the session it was issued for. Do not give an existing device a new `refresh_key` yourself; let the session
service do it.

Every refresh judges the device at one moment, taken when it starts, so application servers should keep synchronised
clocks. The package opens no transaction. If you call `refresh()` inside your own transaction, do not roll it back after
a failed refresh: a rollback also undoes a replay revocation. `DeviceRevoked` is dispatched once the revocation is
committed on the device's own connection: at once outside a transaction, so before `Failed` and `AuthenticationFailed`,
and after the commit inside one, so after them; a rolled-back revocation is never reported, and a transaction on another
connection neither delays nor withdraws it. The transaction that Laravel's `DatabaseTransactions` and `RefreshDatabase`
testing traits wrap around each test does not count either, so a test sees `DeviceRevoked` when the application would.
Under PostgreSQL's REPEATABLE READ, a parallel refresh that commits first makes this one fail with a serialization
error, which surfaces as a server error for you to retry.
