# Refresh Token Transport

## Purpose

This note describes how a guard reads the refresh token from a request: from which sources, what it refuses, and why a
request may carry the token in only one place.

## Invariants

- Each JWT guard reads refresh tokens through one `Http\RefreshTokenTransport`, built from its `refresh_token` settings
  over `authentication.refresh_token` each time it is asked for. A key the guard sets wins, inside `cookie` too. A
  malformed value, a value missing at both levels where one is required, or an unknown key fails closed with an
  `InvalidArgumentException` naming the guard and the key.
- Only the listed sources are read: `cookie`, `body` (the `body_field` of the JSON body, or of the form body of a
  request that may have one; never the query string) and `header`.
- A request that carries a token in more than one listed source is refused as `refresh_token_conflict`, whether or not
  the tokens are equal. The server never chooses between two tokens, so a token cannot reach the exchange through a
  source whose checks it skipped while the request also carries it in the cookie.
- A token read from the cookie must come with an `Origin` that is the request's own (`getSchemeAndHttpHost()`, so
  behind a proxy it needs `TrustProxies`) or one of `allowed_origins`, compared exactly, and with a non-empty
  `csrf_header` header, which a cross-site form cannot send; otherwise `cross_site_request`. The checks come before the
  value is looked at.
- A present value that is not one non-empty string (an empty field, `null`, an array, a header sent twice, a cookie
  that could not be decrypted) is `token_invalid`.
- Reading has no side effects: it changes nothing on the request and runs no query.
- `refresh(string)` stays for a token the caller reads itself and makes none of the cookie's checks, so only
  `refreshFromRequest()` reads the cookie.

## Success Path

- `JwtGuard::refreshFromRequest()` reads the request with the guard's transport.
- No listed source carries a token: it returns `null` and dispatches nothing, as a bearer request without a token.
- One source carries one: the token goes through the same exchange, binding and events as `refresh()`, and the
  `RefreshResult` carries the `RefreshTokenSource` it was read from, so a cookie refresh can be answered with a cookie.
- `Auth::refreshTransport($guard)->read($request)` reads the same way without refreshing.

## Failure / Edge Cases

- A refusal by the transport dispatches `Attempting`, `Failed` and `AuthenticationFailed` (flow `refresh`, the reason,
  the guard and the request's client, no identity) and returns the reason. It reaches no device and no limit.
- A refusal by the exchange returns the exchange's reason after the same events as `refresh()`; `rate_limited` throws
  the 429 there as well.
- A `__Host-` cookie name requires `cookie.path` `/` and no `cookie.domain`, as a browser keeps it only so.
- `cookie.path` is required while the cookie is a source; `allowed_origins` are exact lower-case `scheme://host[:port]`
  values, with no path.

## Implementation Anchors

- `src/Http/RefreshTokenTransport.php`: `read()`.
- `src/Http/RefreshTokenSettings.php`: `forGuard()`.
- `src/Guards/JwtGuard.php`: `refreshFromRequest()`, `refreshTransport()`, `exchangeRefresh()`, `refuseRefresh()`.
- `src/AuthManager.php`: `refreshTransport()`.
- `config/authentication.php`: `refresh_token`.

## Authoritative Tests

- `tests/Unit/Http/RefreshTokenTransportTest.php`
- `tests/Unit/Http/RefreshTokenSettingsTest.php`
- `tests/Feature/Guards/JwtGuardTest.php`
  `testRefreshFromARequestWithoutATokenAttemptsNothing`, `testATokenTheTransportRefusesIsAFailedRefresh`,
  `testARefreshFromTheRequestSaysWhereTheTokenWasRead`
- `tests/Integration/Http/RefreshTokenTransportIntegrationTest.php`
- `tests/Performance/RefreshTokenExchangeQueryBudgetTest.php`
  `testARefreshFromTheRequestCostsWhatARefreshCosts`, `testARequestTheTransportRefusesCostsNoQuery`

## Change Triggers

Update this note when any of the following change:

- the sources a guard may read, or where the body is read from
- how a token carried more than once is treated
- the cookie's origin and custom header checks
- the events and return value of a refusal by the transport
- how the guard and package settings merge
