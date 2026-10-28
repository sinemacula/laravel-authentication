# Refresh Token Transport

## Purpose

This note describes how a guard reads the refresh token from a request: from which sources, what it refuses, and why a
request may carry the token in only one place; and the cookie that carries a browser's refresh token.

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
- A request whose `Cookie` headers carry the refresh cookie more than once is refused as `refresh_token_conflict` too.
  PHP keeps only the first cookie it files under a name, and a browser sends a cookie another host of the site planted
  (a `__Secure-` cookie with the parent `Domain` and a longer `Path`) before the API's own, so the raw headers are
  counted, each name taken as PHP files it (nothing from the first `[` on when a `]` follows it; a `.`, a space or an
  unclosed `[` as `_`). The planted cookie keeps failing refreshes until it expires and the API cannot clear it; a
  `__Host-` name with the path `/` stops other hosts from planting one, at the cost of the cookie riding on every
  request to the API's host.
- A token read from the cookie must come with an `Origin` that is the request's own (`getSchemeAndHttpHost()`, so
  behind a proxy it needs `TrustProxies`) or one of `allowed_origins`, compared exactly, and with a non-empty
  `csrf_header` header, which a cross-site form cannot send; otherwise `cross_site_request`. The checks come before the
  value is looked at.
- A present value that is not one non-empty string (an empty field, `null`, an array, a header sent twice, a cookie
  that could not be decrypted) is `token_invalid`.
- Reading has no side effects: it changes nothing on the request and runs no query.
- `cookie($refreshToken, $device)` makes the refresh cookie: `HttpOnly`, `Secure`, `SameSite=Strict`, the guard's name,
  path and domain, expiring at the earlier of the device's deadlines (read on the write connection), which is the
  refresh token's own `exp`. `forgetCookie()` makes the same cookie, empty and expired; a path limits where a browser
  sends a cookie, not which response may set it, so any route may clear it. Both throw a `LogicException` for a guard
  that does not list `cookie`, and `cookie()` an `InvalidArgumentException` for a session that has ended. Nothing is
  stored on the server.
- `refresh(string)` stays for a token the caller reads itself and makes none of the cookie's checks, so only
  `refreshFromRequest()` reads the cookie for a refresh. A switch of principal is proven by the refresh token too:
  `SessionService::switchPrincipalFromRequest()` reads it with `read()`, so a token from the cookie gets the same
  checks (a refusal is an `AuthenticationFailed` of flow `principal_switch` that touches no device), and its
  `SwitchResult::$source` lets the application answer a switch read from the cookie with `cookie()` (see
  `principal-choice-and-switch.md`).
- `isSameSiteRequest($request)` is the cookie's same-site check on its own (the `Origin` and the `csrf_header`), for a
  route that sets the cookie: the browser sign-in must pass it before signing in, or a cross-site page could auto-submit
  a form with an attacker's credentials and leave the attacker's refresh cookie in the victim's browser (a browser keeps
  a `SameSite=Strict` cookie set by the response to a top-level navigation), where the victim's own scripts would then
  pass every refresh check.
- `logout()` revokes the session's device but cannot reach the response, so the logout route sends `forgetCookie()`
  itself; the revoked device's cookie no longer refreshes (`device_revoked`) wherever the browser keeps it.

## Success Path

- `JwtGuard::refreshFromRequest()` reads the request with the guard's transport.
- No listed source carries a token: it returns `null` and dispatches nothing, as a bearer request without a token.
- One source carries one: the token goes through the same exchange, binding and events as `refresh()`, and the
  `RefreshResult` carries the `RefreshTokenSource` it was read from, so a cookie refresh can be answered with a cookie.
- `Auth::refreshTransport($guard)->read($request)` reads the same way without refreshing.

## Failure / Edge Cases

- A refusal by the transport dispatches `Attempting`, `Failed` and `AuthenticationFailed` (flow `refresh`, the reason,
  the guard and the request's client, no identity) and returns the reason. It reaches no device and no limit.
- A cookie the routes' `EncryptCookies` cannot decrypt arrives as `null` and is `token_invalid`; leave the cookie out
  of encryption, or set and read it on routes that both encrypt.
- A refusal by the exchange returns the exchange's reason after the same events as `refresh()`; `rate_limited` throws
  the 429 there as well.
- A `__Host-` cookie name requires `cookie.path` `/` and no `cookie.domain` on a guard that reads the cookie, as a
  browser keeps it only so. A guard that does not read the cookie never sets it, so a package-wide `__Host-` name does
  not bind it.
- Names PHP renames when it parses a request are refused, since the token would never be found under them: a `.` in the
  cookie or a header name (PHP files it as `_`), and a `.`, a space or a bracket in `body_field` (renamed, or nested,
  in a form body).
- `cookie.csrf_header` must be a custom header: a CORS-safelisted name (`Accept`, `Content-Type`, ...), one the browser
  sets itself (`Origin`, `Cookie`, `Referer`, `Host`, `User-Agent`, any `Sec-` or `Proxy-` name, ...) or
  `Authorization`, compared in any letter case, is refused, since a cross-site form could carry it.
- `cookie.path` is required while the cookie is a source; `allowed_origins` are exact lower-case `scheme://host[:port]`
  values, with no path.

## Implementation Anchors

- `src/Http/RefreshTokenTransport.php`: `read()`, `isSameSiteRequest()`, `cookie()`, `forgetCookie()`.
- `src/Sessions/Concerns/ChoosesPrincipals.php`: `switchPrincipalFromRequest()`.
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
  `testACookiePlantedBesideTheBrowsersOwnIsAConflict`, `testAHostCookieNameLeavesTheGuardsThatDoNotReadTheCookieAlone`
- `tests/Integration/Http/RefreshTokenCookieIntegrationTest.php`
  `testABrowserKeepsItsSessionInTheCookie`, `testTheCookieExpiresWithTheRefreshToken`
- `tests/Integration/Http/RefreshCookieSessionLifecycleTest.php`
  `testASwitchReadFromTheCookieIsAnsweredWithTheCookie`,
  `testASwitchFromAnotherSiteIsRefusedBeforeTheSessionIsTouched`, `testASignInFromAnotherSiteSetsNoCookie`,
  `testLoggingOutRevokesTheSessionAndClearsTheCookie`
- `tests/Performance/RefreshTokenExchangeQueryBudgetTest.php`
  `testARefreshFromTheRequestCostsWhatARefreshCosts`, `testARequestTheTransportRefusesCostsNoQuery`

## Change Triggers

Update this note when any of the following change:

- the sources a guard may read, or where the body is read from
- how a token carried more than once is treated, the cookie sent twice included
- the names the settings accept
- the cookie's origin and custom header checks
- the events and return value of a refusal by the transport
- how the guard and package settings merge
- the refresh cookie's attributes or expiry, or how it is cleared
