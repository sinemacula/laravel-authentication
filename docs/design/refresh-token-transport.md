# Refresh Token Transport

## Purpose

This note describes how an application's refresh token travels: the transport each application uses, what a request is
refused for, why a request may carry the token in only one place and only by the application's own transport, and how
a cookie application's results hand back the cookie instead of the token.

## Invariants

- Each JWT guard (an application) reads refresh tokens through one `Http\RefreshTokenTransport`, built from its
  `refresh_token` settings over `authentication.refresh_token` each time it is asked for. A key the guard sets wins,
  inside `cookie` too. A malformed value, a value missing at both levels where one is required, or an unknown key fails
  closed with an `InvalidArgumentException` naming the guard and the key.
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
  value is looked at. The rule is `isSameSiteClient(ClientContext)`, judged on the facts `ClientContext::fromRequest()`
  reads: the `Origin` as presented (kept only when 1 to 512 printable ASCII characters, never cut), the request's own
  scheme and host (`null` when the request has no host or Symfony refuses the host or forwarded headers), and the names
  of the headers whose first value is a non-empty string (lower case, `_` read as `-`, never their values); the guard's
  configured `csrf_header` is applied when judging. A missing fact fails it. `isSameSiteRequest($request)` is the same
  rule on those facts of the request, read without its IP address, which Symfony would refuse on a first read for a
  trusted proxy's conflicting forwarded client addresses. The scheme and host are read from a copy of the request:
  Symfony throws a refused host or conflicting forwarded headers only on a request's first read and answers an empty
  host after, so reading the request itself would take that refusal from the application and give every later read an
  empty host.
- A present value that is not one non-empty string (an empty field, `null`, an array, a header sent twice, a cookie
  that could not be decrypted) is `token_invalid`. A token read is a `PresentedRefreshToken` holding it as a `Secret`.
- Reading has no side effects: it changes nothing on the request and runs no query.
- The cookie is host-only (never a `Domain`). Its name is `cookie.name`, or derived from the guard:
  `__Host-<guard>_refresh_token` for a cookie application on the path `/`, otherwise `__Secure-<guard>_refresh_token`,
  so two browser applications on one host never overwrite each other's cookie. A body application derives a name too,
  since it refuses its own cookie as a mismatch. A cookie application whose guard name makes no cookie name needs
  `cookie.name`; a body application with such a name looks for no cookie, since it never sets one to refuse; two cookie
  applications with equal names fail closed naming both guards (only the other guards' `transport`, `cookie.name` and
  `cookie.path` are read for this); an explicit `__Host-` name needs the path `/` on a cookie application; a cookie
  application needs a `cookie.path`.
- A cookie application's results never carry the plain refresh token. The session service's builders make the full
  pair; `deliver()` moves the refresh token into an `Http\RefreshCookie` (the token as a `Secret`, the name, the path,
  and the expiry: the earlier of the session's deadlines, read on the write connection, which is the token's own
  `exp`) at the three places a result leaves the service: `SessionService::bound()` (sign-in, `start()`, activation by
  `satisfy()` and `choose()`), `SessionRefresh` (refresh) and `SessionService::switched()` (switch), keeping the
  pair's `expiresAt` and `expiresIn`, which are the access token's. `RefreshCookie`
  makes the Symfony `Cookie` only on `cookie()`, since a `Cookie` shows its value to dumps and serialises it;
  `attachTo()` adds it to a response and marks the response `no-store`. `deliver()` adds no query.
- `forgetCookie()` makes the same cookie, empty and expired; a path limits where a browser sends a cookie, not which
  response may set it, so a route outside the path may clear it. A response may carry it only for a request that
  signed its session out by its access token (which a cross-site page cannot send) or that passes
  `isSameSiteRequest()` (`isSameSiteClient()` for a client handed in as plain values), or a cross-site form could sign
  the browser out; `SessionSignOut` attaches it on those terms, and the guides tell a route of the application's own to
  do the same. It throws a `LogicException` for a body application, and `deliver()` an `InvalidArgumentException` for a
  session that has ended.
- Every action that takes a refresh token takes it as a plain value, on either transport: `refresh()`, `switchTo()`,
  `signOutWith()` and the `@internal` `refreshCredential()` behind `Auth::caller()` take what `extract()` answered (the
  private `carrier()` step, conflict, mismatch or the one source, then the value; never a same-site judgement), or a
  `PresentedRefreshToken` the application built (`fromBody()` for a body application's own read), and a
  `ClientContext`. Nothing reads the guard's request. A `PresentedRefreshToken` carries `carriers`, every carrier the
  request carried a token in (required by its constructor, `[$source]` from `extract()` and `fromBody()`), so a value
  the application built is judged on conflicts too: `judge()` refuses carriers that are not the source alone
  (`refresh_token_conflict`), then a source that is not one of the application's carriers, a header included when
  `header` is `null`, and a body token on a cookie application (`refresh_transport_mismatch`), then a cookie whose
  client fails `isSameSiteClient()` (`cross_site_request`), and is pure. A reason handed in must be one `extract()`
  answers (`SessionRefresh::handedIn()`: conflict, mismatch, `token_invalid`; `InvalidArgumentException` before
  anything is dispatched). A token `extract()` answered from a request of the API's own site passes `judge()` with that
  request's `ClientContext`.
- The cookie, the application and the session agree on every refresh and switch: the cookie read is the application's
  own and unique; the carrier is its transport; the token's `client_id` is the application (`token_invalid`); the
  session it names is the application's (`session_guard_mismatch`); and the cookie a result sets is that
  application's.
- Every path that sets a cookie application's refresh cookie from credentials or a pending session is held to the same
  rule by the package: `signIn()`, `start()`, `satisfy()` and `choose()` refuse as `cross_site_request`
  (`SessionPreconditions::crossSite()`) after the transport is built and before the package's first read or write (only
  the driver's resolution, the identifier's extraction and `Attempting` listeners, the application's code, run before it
  on `signIn()`), and refresh, switch and sign-out judge the token through `judge()`, which makes the same checks on the
  client given. Without it a cross-site page could
  auto-submit a form with an attacker's credentials and leave the attacker's refresh cookie in the victim's browser (a
  browser keeps a `SameSite=Strict` cookie set by the response to a top-level navigation), where the victim's own
  scripts would then pass every refresh check. `signIn()` and `start()` judge the `SignInContext`'s client, `satisfy()`
  and `choose()` the `ClientContext` they are given, each a required plain value. The check is pure (no query,
  no lock, no event of its own) and fails closed. A body application is never refused. `signInExternally()` is exempt:
  an external provider's callback is a cross-site top-level navigation by design, so the defence is the adapter's to
  keep, and the guides require it of an adapter that calls `signInExternally()`: it binds its `state` and nonce to the
  browser that began the flow, refuses a callback that does not match them, and redeems the result once, through a
  single-use handoff, for that browser. `isSameSiteRequest()` and `isSameSiteClient()` stay public for an application's
  own routes, such as one that clears the cookie.
- The pending credential is never a cookie: a cookie application's pending results carry it in the body.

## Success Path

- A controller extracts the request's token (`Auth::refreshTransport($guard)->extract($request)`) and builds its
  `ClientContext`; `SessionService::refresh($presented, $client)` builds the transport from the configuration
  (`RefreshTokenTransport::forGuard()`), as the switch and the sign-out build it.
- Nothing presented: it returns `null` and dispatches nothing, as a bearer request without a token.
- A token the judgement accepts goes through the exchange, binding and events, and the `RefreshResult` carries the
  `RefreshTokenSource` it was presented from (`source`); a cookie application's refreshed pair carries the
  `RefreshCookie` to attach.
- `refresh()`, `switchTo()` and `signOutWith()` judge the token with `judge()` and then go through the exchange, the
  switch, or proof and revocation, with the client given: the attempt limit, `Refreshed`, `SignedIn`,
  `PrincipalSwitched`, `AuthenticationFailed`, `SessionRevoked` and `SessionReturnedToPending` carry it
  (`PendingTransitions` built with it, `forClient()` for a switch), and so does the guard's bind: `SessionRefresh` hands
  it to `GuardBinding::loginVerified()` and the switch to `authenticateAs()`, so `PrincipalAssigned` and
  `SessionAuthenticated`, and the last use `SessionAuthenticated` records, are that client's, as they are for
  `signIn()`, `start()` and
  `signInExternally()` given a `SignInContext`. The client is a parameter of that one bind, never guard state, so the
  guard's later events (and the next request on a long-lived worker) describe its own request. A cookie application's
  refreshed pair carries the `RefreshCookie`; a sign-out's result the expired cookie only for a same-site client whose
  token was not refused as a conflict. A sign-out binds nothing.

## Failure / Edge Cases

- A refusal by the judgement dispatches `Attempting`, `Failed` and `AuthenticationFailed` (flow `refresh`, the reason,
  the guard and the client given, no identity) and returns a failed `RefreshResult` with the reason and the `source` it
  was presented from; a reason handed in, the same with no `source`. A switch's refusal dispatches only
  `AuthenticationFailed` (flow `switch`), a sign-out's only `AuthenticationFailed` (flow `sign_out`).
  It reaches no session and no limit.
- A plain refusal (a reason handed in, or `judge()`'s) is reported with the client given and costs no query; a refused
  token's result carries its `source`, a reason handed in none. `null` answers `null` (refresh) or nothing signed out,
  dispatching nothing.
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

- `src/Http/RefreshTokenTransport.php`: `extract()`, `judge()`, `usesCookie()`, `deliver()`,
  `isSameSiteRequest()`, `isSameSiteClient()`, `forgetCookie()`; `src/Http/PresentedRefreshToken.php`;
  `src/Http/ClientContext.php`: `fromRequest()`, `sameSiteFactsOf()`, `carriesHeader()`;
  `src/Sessions/SessionPreconditions.php`: `crossSite()`; `src/Http/RefreshCookie.php`; `src/Http/Enums/Transport.php`;
  `src/Jwt/TokenPair.php`; `src/Http/RequestBody.php` (the body fields and the field names, shared with the pending
  credential's field).
- `src/Sessions/SessionService.php`: `signIn()`, `start()`, `satisfy()`, `choose()`, `bound()`;
  `src/Sessions/Concerns/SwitchesSessions.php`: `switchTo()`, `refuseSwitch()`, `switched()`;
  `src/Sessions/SessionRefresh.php`: `refresh()`, `credential()`, `handedIn()`; and `src/Sessions/SessionSignOut.php`:
  `signOutWith()`; which build the application's transport from the
  configuration (`RefreshTokenTransport::forGuard()`), as the guard's own factory does.
- `src/Http/RefreshTokenSettings.php`: `forGuard()`.
- `src/Guards/JwtGuard.php`: `refreshTransport()`.
- `src/AuthManager.php`: `refreshTransport()`.
- `config/authentication.php`: `refresh_token`.

## Authoritative Tests

- `tests/Unit/Http/RefreshTokenTransportTest.php`, `tests/Unit/Http/ClientContextTest.php`,
  `tests/Unit/Sessions/SessionPreconditionsTest.php`
- `tests/Feature/Sessions/SessionServiceTest.php`: each cookie-setting path refused cross-site with nothing written, a
  body application unaffected, `signInExternally()` exempt; `tests/Performance/SessionServiceQueryBudgetTest.php`: a
  refused sign-in, `start()`, `satisfy()` or `choose()` costs no query
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
- the cookie's origin and custom header checks, or the paths held to them
- the events and return value of a refusal by the transport
- how the guard and package settings merge
- the refresh cookie's name, attributes or expiry, how it is delivered, or how it is cleared
