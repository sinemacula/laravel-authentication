# Refresh Token Transport

## Purpose

This note describes how an application's refresh token travels: the transport each application uses, what a request is
refused for, why a request may carry the token in only one place and only by the application's own transport, and how
a cookie application's results hand back the cookie instead of the token.

## Invariants

- Each JWT guard (an application) reads refresh tokens through one `Http\RefreshTokenTransport`, built from its
  `refresh_token` settings over `authentication.refresh_token` each time it is asked for. A key the guard sets wins,
  inside `cookie` too. A malformed value, a value missing at both levels where one is required, or an unknown key (the
  removed `sources` and `cookie.domain` among them) fails closed with an `InvalidArgumentException` naming the guard and
  the key.
- `transport` is `body` (the default; the `body_field` of the JSON body, or of the form body of a request that may have
  one, never the query string, or the `header` when one is set) or `cookie` (`Http\Enums\Transport`). A browser
  application opts in to the cookie.
- Every request is read in all three carriers, whatever the transport: the application's cookie, the body field and
  the header. A request that carries a token in more than one is refused as `refresh_token_conflict`, whether or not
  the tokens are equal: the server never chooses between two tokens, and a cookie arriving with a body credential is
  never read. A request whose `Cookie` headers carry the application's cookie more than once is refused the same way:
  PHP keeps only the first cookie it files under a name, and a browser sends a cookie another host of the site planted
  before the API's own, so the raw headers are counted, each name taken as PHP files it (nothing from the first `[` on
  when a `]` follows it; a `.`, a space or an unclosed `[` as `_`).
- One carrier that is not the application's transport (the cookie to a body application, the body or the header to a
  cookie application) is refused as `refresh_transport_mismatch`, before the cookie's checks or the value.
- A token read from the cookie must come with an `Origin` that is the request's own (`getSchemeAndHttpHost()`, so
  behind a proxy it needs `TrustProxies`) or one of `allowed_origins`, compared exactly, and with a non-empty
  `csrf_header` header, which a cross-site form cannot send; otherwise `cross_site_request`. The checks come before the
  value is looked at.
- A present value that is not one non-empty string (an empty field, `null`, an array, a header sent twice, a cookie
  that could not be decrypted) is `token_invalid`. A token read is a `PresentedRefreshToken` holding it as a `Secret`.
- Reading has no side effects: it changes nothing on the request and runs no query.
- The cookie is host-only (never a `Domain`). Its name is `cookie.name`, or derived from the guard:
  `__Host-<guard>_refresh_token` for a cookie application on the path `/`, otherwise `__Secure-<guard>_refresh_token`,
  so two browser applications on one host never overwrite each other's cookie. A body application derives a name too,
  since it refuses its own cookie as a mismatch. A guard name that makes no cookie name needs `cookie.name`; two cookie
  applications with equal names fail closed naming both guards (only the other guards' `transport`, `cookie.name` and
  `cookie.path` are read for this); an explicit `__Host-` name needs the path `/` on a cookie application; a cookie
  application needs a `cookie.path`.
- A cookie application's results never carry the plain refresh token. The session service's builders make the full
  pair; `deliver()` moves the refresh token into an `Http\RefreshCookie` (the token as a `Secret`, the name, the path,
  and the expiry: the earlier of the session's deadlines, read on the write connection, which is the token's own
  `exp`) at the three places a result leaves the service: `SessionService::bound()` (sign-in, `start()`, activation by
  `satisfy()` and `choose()`), `SessionRefresh` (refresh) and `SessionService::switched()` (switch). `RefreshCookie`
  makes the Symfony `Cookie` only on `cookie()`, since a `Cookie` shows its value to dumps and serialises it;
  `attachTo()` adds it to a response and marks the response `no-store`. `deliver()` adds no query.
- `forgetCookie()` makes the same cookie, empty and expired; a path limits where a browser sends a cookie, not which
  response may set it, so any route may clear it. It throws a `LogicException` for a body application, and `deliver()`
  an `InvalidArgumentException` for a session that has ended.
- A cookie application's token is read only from its cookie, through the transport: `refresh(string)`,
  `switchTo(string, SwitchTarget)` and `signOutWith(string)` throw a `LogicException` on a cookie application
  (`SessionRefresh::refuseHandedIn()`, the one place it is thrown); `refreshFromRequest()`, `switchFromRequest()`,
  `signOutFromRequest()` and `refreshCredentialFromRequest()` (the `me` route binding's read) take a private path. A
  body application's `refresh(string)` is for a token the caller reads itself.
- The cookie, the application and the session agree on every refresh and switch: the cookie read is the application's
  own and unique; the carrier is its transport; the token's `client_id` is the application (`token_invalid`); the
  session it names is the application's (`session_guard_mismatch`); and the cookie a result sets is that
  application's.
- `isSameSiteRequest($request)` is the cookie's same-site check on its own (the `Origin` and the `csrf_header`), for a
  route that sets the cookie: the browser sign-in must pass it before signing in, or a cross-site page could auto-submit
  a form with an attacker's credentials and leave the attacker's refresh cookie in the victim's browser (a browser keeps
  a `SameSite=Strict` cookie set by the response to a top-level navigation), where the victim's own scripts would then
  pass every refresh check. The package cannot impose it on `start()`, whose external provider's callback is a
  cross-site top-level navigation, so it stays the application's check on the routes that set the cookie.
- The pending credential is never a cookie: a cookie application's pending results carry it in the body.

## Success Path

- `SessionService::refreshFromRequest()` reads the request with the application's transport, built from the
  configuration (`RefreshTokenTransport::forGuard()`) as the switch builds it.
- No carrier carries a token: it returns `null` and dispatches nothing, as a bearer request without a token.
- The application's carrier carries one: the token goes through the same exchange, binding and events as `refresh()`,
  and the `RefreshResult` carries the `RefreshTokenSource` it was read from (`source`); a cookie application's
  refreshed pair carries the `RefreshCookie` to attach.
- `Auth::refreshTransport($guard)->read($request)` reads the same way without refreshing.

## Failure / Edge Cases

- A refusal by the transport dispatches `Attempting`, `Failed` and `AuthenticationFailed` (flow `refresh`, the reason,
  the guard and the request's client, no identity) and returns a failed `RefreshResult` with the reason and no `source`.
  It reaches no session and no limit.
- A cookie the routes' `EncryptCookies` cannot decrypt arrives as `null` and is `token_invalid`; leave the cookie out
  of encryption, or set and read it on routes that both encrypt.
- A refusal by the exchange returns the exchange's reason after the same events as `refresh()`, `rate_limited` with its
  `retryAfter`, for the route to answer with a 429; nothing is thrown.
- Names PHP renames when it parses a request are refused, since the token would never be found under them: a `.` in the
  cookie or a header name (PHP files it as `_`), and a `.`, a space or a bracket in `body_field` (renamed, or nested,
  in a form body).
- `cookie.csrf_header` must be a custom header: a CORS-safelisted name (`Accept`, `Content-Type`, ...), one the browser
  sets itself (`Origin`, `Cookie`, `Referer`, `Host`, `User-Agent`, any `Sec-` or `Proxy-` name, ...) or
  `Authorization`, compared in any letter case and with `_` read as `-` (as Symfony reads a header name), is refused,
  since a cross-site form could carry it.
- `allowed_origins` are exact lower-case `scheme://host[:port]` values, with no path.

## Implementation Anchors

- `src/Http/RefreshTokenTransport.php`: `read()`, `usesCookie()`, `deliver()`, `isSameSiteRequest()`,
  `forgetCookie()`; `src/Http/RefreshCookie.php`; `src/Http/Enums/Transport.php`; `src/Jwt/TokenPair.php`.
- `src/Sessions/SessionService.php`: `bound()`; `src/Sessions/Concerns/SwitchesSessions.php`: `switchTo()`,
  `switchFromRequest()`, `switched()`; `src/Sessions/SessionRefresh.php`: `refresh()`, `refreshFromRequest()`,
  `credentialFromRequest()`, `refuseHandedIn()`; and `src/Sessions/SessionSignOut.php`: `fromRequest()`, `with()`;
  which build the application's transport from the configuration (`RefreshTokenTransport::forGuard()`), as the guard's
  own factory does.
- `src/Http/RefreshTokenSettings.php`: `forGuard()`.
- `src/Guards/JwtGuard.php`: `refreshTransport()`.
- `src/AuthManager.php`: `refreshTransport()`.
- `config/authentication.php`: `refresh_token`.

## Authoritative Tests

- `tests/Unit/Http/RefreshTokenTransportTest.php`
- `tests/Unit/Http/RefreshTokenSettingsTest.php`
- `tests/Unit/Http/RefreshCookieTest.php`
- `tests/Unit/Jwt/TokenPairTest.php`
- `tests/Feature/Sessions/CookieTransportTest.php`
- `tests/Feature/Guards/JwtGuardTest.php`
  `testRefreshFromARequestWithoutATokenAttemptsNothing`, `testATokenTheTransportRefusesIsAFailedRefresh`,
  `testARefreshFromTheRequestSaysWhereTheTokenWasRead`
- `tests/Feature/Sessions/SessionRefreshTest.php`
  `testARefreshFromTheRequestSaysWhereItsTokenWasRead`, `testARequestWithoutATokenIsNotARefresh`,
  `testATokenTheTransportRefusesIsARefusedRefresh`
- `tests/Integration/Http/RefreshTokenTransportIntegrationTest.php`
  `testACookiePlantedBesideTheBrowsersOwnIsAConflict`, `testAHostCookieNameLeavesTheBodyApplicationsAlone`,
  `testACookieApplicationOnTheRootPathDerivesAHostName`, `testACookieRefreshFromTheOwnOriginIsExchanged`
- `tests/Integration/Http/RefreshTokenCookieIntegrationTest.php`
  `testABrowserKeepsItsSessionInTheCookie`, `testTheCookieExpiresWithTheRefreshToken`,
  `testTwoBrowserApplicationsOnOneHostKeepSeparateCookies`
- `tests/Integration/Http/RefreshCookieSessionLifecycleTest.php`
  `testASwitchReadFromTheCookieIsAnsweredWithTheCookie`,
  `testASwitchFromAnotherSiteIsRefusedBeforeTheSessionIsTouched`, `testASignInFromAnotherSiteSetsNoCookie`,
  `testLoggingOutRevokesTheSessionAndClearsTheCookie`
- `tests/Performance/RefreshTokenExchangeQueryBudgetTest.php`
  `testARefreshFromTheRequestCostsWhatARefreshCosts`, `testACookieRefreshCostsWhatARefreshCosts`,
  `testARequestTheTransportRefusesCostsNoQuery`

## Change Triggers

Update this note when any of the following change:

- the transports an application may use, the carriers read, or where the body is read from
- how a token carried more than once is treated, the cookie sent twice included
- the names the settings accept
- the cookie's origin and custom header checks
- the events and return value of a refusal by the transport
- how the guard and package settings merge
- the refresh cookie's name, attributes or expiry, how it is delivered, or how it is cleared
