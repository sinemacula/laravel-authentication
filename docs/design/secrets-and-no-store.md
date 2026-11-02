# Secrets and No-Store

## Purpose

This note records how the package hands out a secret (a token, a pending credential, an API key, a one-time code, a
reset token, a signed link) so that it reaches the client and nothing else: no log, trace, dump, cache, queue payload or
stored response. It covers the `Secret` value object, the response helpers and the `authentication.no-store` middleware,
which values are secrets and which stay strings, and what the redaction tests check.

## Invariants

- Every secret the package returns is a `Secrets\Secret`: the access and refresh tokens of a `TokenPair` (and every
  token `JwtTokenService` issues, the machine token of a client credentials grant included), the pending credential of a
  `SignInResult`, `RefreshResult` or `SwitchResult`, the access token of a step-up, a reauthentication or a client
  credentials grant, an `IssuedApiKey`'s key, a `OneTimeCodeMessage`'s code, a `PasswordResetLink`'s token, an
  identifier change's signed link, a verification link and a `PresentedRefreshToken`'s token. A `RefreshCookie` holds
  its token as one and makes the Symfony `Cookie` (which dumps and serialises its value) only on `cookie()`.
- A `Secret` holds its value in a private `\SensitiveParameterValue` and gives it up only through `reveal()`. Casting it
  to a string, encoding it as JSON, serialising it or unserialising one throws `Exceptions\SecretNotRevealedException`
  (a `LogicException`): each is a bug in the calling code, and an exception is a safer failure than a body that silently
  carries `[redacted]` in place of a token. `__debugInfo()` is `['secret' => '[redacted]']` (`Secret::REDACTED`), which
  `var_dump`, `print_r` and Symfony's VarDumper (behind `dump` and `dd`) show; `var_export` shows an empty
  `\SensitiveParameterValue`. An empty secret is an `InvalidArgumentException`.
- No object the package builds holds a secret in a plain property, since `#[\SensitiveParameter]` hides only the
  annotated argument of its own frame: an object passed on is recorded whole by a trace, and a closure's captures are
  not covered at all. So a returned secret is a `Secret`; an input is a private `\SensitiveParameterValue` behind an
  accessor (`SignInRequest::input()`); an internal value is held in a private `Secret` (`IssuedCode`, read through
  `code()` and `secret()`, whose explicit `__serialize()` and `__unserialize()` write and read the plaintext only for the
  encrypted delivery job, and whose `__debugInfo()` redacts it); and a closure that needs a password or a pending
  credential captures the `\SensitiveParameterValue`, never the string.
- Values the application hands in (a password, a sign-in's input, a refresh token or pending credential a request
  carried) stay strings, covered by `#[\SensitiveParameter]` on every parameter that receives one. A method that takes
  back a token or credential the package returned (`refresh()`, `switchTo()`, `signOutWith()`, `pending()`,
  `satisfy()`, `choose()`, `discard()`, `JwtTokenService::parse()`) takes it as the `Secret` it was returned as or as
  the string a request carried, and reveals it only at the step that reads it (`Secrets\Plaintext`), so a token read
  through the transport reaches the parser as a `Secret`. A credential id (an
  API key's or a passkey's) and a refresh token's rotation id are identifiers, not secrets, and stay strings.
- Events never carry a secret, and `JwtTokenService`'s debug logger is never handed a token.
- `ClientCredentialsResult` keeps `JsonSerializable` with the token still a `Secret`, so encoding a granted result
  throws and a refused one encodes as its error body; `toArray()` is the explicit reveal into the RFC 6749 body, and
  `toResponse()` sends it through `SecretResponse::json()`. It is not `Arrayable`, so `response()->json($result)` cannot
  reveal it on the way past `toResponse()`'s no-store.
- `SecretResponse::json($data, $status, $headers)` reveals every `Secret` in `$data` at any depth of arrays and marks
  the response `Cache-Control: no-store` and `Pragma: no-cache`, replacing whatever caching the response allowed;
  `withoutStoring($response)` marks a response built some other way. `RefreshCookie::attachTo()` and
  `ClientCredentialsResult::toResponse()` mark their responses the same way.
- `Http\Middleware\NoStore` (alias `authentication.no-store`) marks every response of the routes that list it and reads
  no body. It is opt-in per route. The provider puts it first in the HTTP kernel's middleware priority once the kernel
  is resolved (after the application's `withMiddleware()` settings, which run when the kernel is first made), so on a
  route that lists it, it wraps every other sorted route middleware and sets the headers last: the `401` of `auth`, a
  refused binding's `404`, an early answer of a later middleware and an error a controller raises all leave through it.

## Success Path

- A route answers a sign-in with `SecretResponse::json(['access_token' => $tokens->accessToken, ...])`: the body carries
  the plaintext and the response is never stored.
- A cookie application's route answers with `$tokens->refreshCookie->attachTo(SecretResponse::json([...]))`.
- A route that returns another package's secrets lists `authentication.no-store`.

## Failure / Edge Cases

- `json_encode($result)`, `response()->json(['token' => $secret])`, `(string) $secret`, a `Secret` put in a queued job,
  the cache or the session: `SecretNotRevealedException`, before anything is sent or stored.
- The kernel sorts only middleware in its priority list, so `NoStore` wraps a middleware of the application's own only
  when the route lists it first. Global middleware runs outside route middleware altogether. An application that
  replaces the priority list after the kernel is resolved must put `NoStore` first itself; one that is not the
  foundation kernel is left as it is.
- A request's own input is reachable from a trace's frames through the container: that is the application's request, not
  something the package built.

## Implementation Anchors

- `src/Secrets/Secret.php`, `src/Secrets/SecretResponse.php`, `src/Secrets/Plaintext.php`,
  `src/Exceptions/SecretNotRevealedException.php`
- `src/Http/Middleware/NoStore.php`; `src/AuthenticationServiceProvider.php` (`registerMiddleware()`)
- `src/Http/RefreshCookie.php`, `src/ClientCredentials/ClientCredentialsResult.php`, `src/Sessions/SignInRequest.php`,
  `src/Codes/IssuedCode.php`

## Authoritative Tests

- `tests/Unit/Secrets/SecretTest.php`, `tests/Unit/Secrets/SecretResponseTest.php`, `tests/Unit/Secrets/PlaintextTest.php`,
  `tests/Unit/Exceptions/SecretNotRevealedExceptionTest.php`
- `tests/Feature/Http/Middleware/NoStoreTest.php`, `tests/Feature/AuthenticationServiceProviderMiddlewareTest.php`
- `tests/Feature/Secrets/SecretRedactionTest.php`: a throwing sign-in method and throwing listeners during a sign-in,
  refresh, switch, activation and sign-out leave no secret in the trace's arguments, captures or dumped object graphs;
  no event carries a secret
- `tests/Unit/Jwt/JwtTokenServiceTest.php` `testTheLoggerIsNeverHandedAToken`
- `tests/Unit/Codes/IssuedCodeTest.php`, `tests/Unit/Sessions/SignInRequestTest.php`,
  `tests/Unit/Http/RefreshCookieTest.php`, `tests/Unit/ClientCredentials/ClientCredentialsResultTest.php`

## Change Triggers

Update this note when any of the following change:

- which values the package hands out as a `Secret`, or a new secret it returns
- what a `Secret` refuses, or what it shows to a dump
- how a secret is revealed into a response, or which helpers set no-store
- where `authentication.no-store` sits in the kernel's middleware priority
