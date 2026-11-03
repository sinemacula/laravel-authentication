# Machine credentials

## Non-human identities

An API client or a service account is an identity of its own type: implement `Contracts\MachineIdentity` on its model
(a marker that extends `Identity`). A non-human identity has no password, no interactive sign-in, no session and no
refresh; it authenticates only with a credential issued to it, each bound to one principal in one tenant. The package
enforces this at every entry point that verifies something:

| Entry point                                                        | A non-human identity is                                      |
|--------------------------------------------------------------------|--------------------------------------------------------------|
| A password check (`signIn('password')`, `attempt()`, `validate()`) | refused as `invalid_credentials`, no hash computed, no count |
| Any other sign-in method, `start()`, `satisfy()`, `choose()`       | refused at admission as `machine_identity`                   |
| A refresh or a switch on a session it owns                         | refused as `machine_identity`                                |
| A session's access token (`jwt` guard) naming it                   | refused as `machine_identity`                                |
| `Auth::jwt()->issueAccessToken()` / `issueRefreshToken()`          | refused with a `LogicException`                              |
| An `api_key` guard's `attempt()`                                   | refused as `method_not_allowed`: machines do not sign in     |
| A one-time code for sign-in                                        | never delivered; one it holds anyway is refused at admission |
| `Auth::codes()->sendVerification()` / `verify()`                   | refused with an `InvalidArgumentException`                   |
| Registering, listing or removing passkeys, or a passkey factor     | refused with an `InvalidArgumentException`: it holds none    |
| `Auth::identifierChanges()`, every method                          | refused with an `InvalidArgumentException`: it has none      |

The trusted binds stay trusted: `login()`, `setUser()` and `authenticateAs()` (and so Laravel's `actingAs()` in tests)
bind a machine as given, limited to no scope (`Auth::scopes()` is `[]`), since the caller has proven it;
`authenticateAs()` limits it to the scopes it is given instead, when it is given some.

## Credential scopes

A credential issued to a machine (an API key, or the access token a client credentials exchange hands out) carries
scopes: the most its bearer may do. The package carries them and never interprets them. A scope is an opaque string
(`invoices:read`, `https://api.example.test/reports`), an RFC 6749 scope token: printable ASCII other than space, `"`
and `\`, at most 255 bytes, kept as an ordered list without duplicates and written as one space-separated string in a
token's `scope` claim. That string may be at most 8,192 bytes: a longer list is refused with an `InvalidScopeException`
when the key is issued, so it is always stored whole. A client credentials token carries the list in its claims, so one
granting a long list can outgrow a proxy's limit on a request header line (8 KB under nginx's and Apache's defaults,
which a token reaches once its list passes about 5,800 bytes); keep the scopes a client asks for short, or raise that
limit. Scopes are a ceiling, never a permission: authorisation computes the principal's permissions and intersects them
with the credential's scopes, so a scope grants nothing the principal could not already do.

`Auth::scopes()` (and `scopes()` on a package guard) reports them for the request:

| The request authenticated with                                   | `Auth::scopes()`         |
|------------------------------------------------------------------|--------------------------|
| A human identity's session token, or a trusted bind of a human   | `null`: no ceiling       |
| An API key, or a client credentials access token                 | the granted list         |
| A non-human identity bound without a credential (`login()`, ...) | `[]`: limited to nothing |
| Nothing, or a guard that is not the package's                    | `null`                   |

`[]` and `null` differ: `[]` is a credential that grants no scope, `null` is no credential limit at all. A
`MachineIdentity` is never left without a ceiling, so binding one through the trusted `login()`, `setUser()` or
`authenticateAs()` (Laravel's `actingAs()` in tests, say) gives it `[]`;
`authenticateAs($identity, $principal, $session, $scopes)` gives it the scopes named instead (a test acting as a machine
with scopes, say; see [Testing](testing.md)), and refuses scopes for a human identity with an
`InvalidArgumentException`. The scopes are also in every event's context (`$event->context->scopes`), with the
credential's id in `credentialId`.

Scopes are checked when a credential is issued: each must be a well-formed scope token, and the bound
`ScopeRegistry` may reject any of them for the principal on the guard. The default, `AcceptAnyScope`, accepts every
well-formed scope; an authorisation package binds its own so keys can only carry scopes that name real permissions:

```php
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;

final class PermissionScopes implements ScopeRegistry
{
    public function rejected(string $guard, Principal $principal, array $scopes): array
    {
        return array_values(array_diff($scopes, Permission::names()));
    }
}

$this->app->singleton(ScopeRegistry::class, PermissionScopes::class);
```

Any answer but `[]` refuses the credential, whatever it names: a scope given (named in the exception), or a pattern or a
form of its own (every scope given is named then). A malformed or rejected scope throws
`Exceptions\InvalidScopeException` (an `InvalidArgumentException`) naming the offending scopes in `$exception->scopes`:
issuing a credential is a trusted, programmatic action, so this is the caller's error, not a failed authentication. A
credential's scopes are fixed for its life.

## API keys

An API key authenticates a non-human identity, a model that implements `Contracts\MachineIdentity`, as one of its
principals on one guard. Issue keys through the guard's key service, `Auth::apiKeys($guard)`, for an `api_key` guard
(whose requests present the key) or a `jwt` guard (whose client credentials exchange takes it, see
[Client credentials](#client-credentials)):

```php
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;

$issued = Auth::apiKeys('machine')->issue(
    identity: $client,                 // a MachineIdentity
    principal: $client,                // the principal the key acts as (the client itself in 2D)
    scopes: ['invoices:read'],
    name: 'Billing sync',
    expiresAt: now()->addYear(),       // optional; never expires without it
);

$issued->key();    // a Secret: reveal() gives ak_k3j9x0m2p8q4r7t1_9fJ2kL8mN3pQ7rS1tV5wX0yZ4aB6cD8eF2gH4iJ6 - show it once
$issued->summary;  // ApiKeySummary: id, public id, guard, name, scopes, expiry, last use, rotation, revocation

return SecretResponse::json(['key' => $issued->key(), 'summary' => $issued->summary->toArray()], 201);
```

A key is `<prefix>_<public>_<secret>`: the configured prefix (`ak` by default), 16 random lower-case letters or digits,
and a 40-character random secret. Only `<prefix>_<public>` (the summary's `publicId`) and the SHA-256 digest of the
secret are stored, so the key is shown once and cannot be shown again; a secret of about 238 bits needs no password hash
to resist guessing. `IssuedApiKey` holds the key as a `Secret` (see [Secrets in
responses](signing-in.md#secrets-in-responses)), so no dump of it (`dump()`, `print_r`, `var_export`) shows the key,
casting, encoding or serialising it throws, and `SecretResponse::json()` reveals it into a response that is never
stored. The principal must be one the identity acts as on the guard (resolved through the guard's principal resolver, as
a pinned principal is) and one the application admits; the key records the identity, the principal and the principal's
tenant, each by type and identifier, and the guard, and authenticates only as them, on that guard. A tenant's type is
its morph class, or its class name when it is not an Eloquent model, so a tenant of another type that shares the
identifier is not the recorded one. A malformed or past expiry, a principal the identity does not act as or the
application does not admit, a name that is empty, longer than 255 characters, not valid UTF-8 or holds a NUL byte, and a
malformed or rejected scope (see [Credential scopes](#credential-scopes)) are each an `InvalidArgumentException`:
issuing is a trusted, programmatic action.

A request presents the key as a bearer credential, `Authorization: Bearer <key>`, on a route the guard protects
(`auth:machine`). The guard reads the key's public part with one indexed lookup on the write connection, compares the
digest of the secret in constant time, and then requires, in order:

| Check                                                                         | Failure reason              |
|-------------------------------------------------------------------------------|-----------------------------|
| the key is in form, its public part names a key, and the secret is that key's | `credential_invalid`        |
| the key was issued for this guard                                             | `credential_guard_mismatch` |
| it is not revoked                                                             | `credential_revoked`        |
| it has not expired (from the second its expiry names)                         | `credential_expired`        |
| the application lists `api_key` in `methods`                                  | `method_not_allowed`        |
| the provider returns exactly the owner the key records                        | `identity_unknown`          |
| the owner is a `MachineIdentity`                                              | `credential_invalid`        |
| the owner is active                                                           | `identity_inactive`         |
| the principal resolves exactly to the one the key records                     | `principal_mismatch`        |
| the principal is active                                                       | `principal_inactive`        |
| its tenant, if any, is active                                                 | `tenant_inactive`           |
| the principal and its tenant are, by type and identifier, the ones recorded   | `principal_mismatch`        |
| the application admits the principal                                          | `principal_ineligible`      |

The last check reports the reason the application policy gives: `principal_ineligible` for a principal a policy of your
own keeps out (see [Extending](extending.md#deciding-which-principals-may-use-an-application)), the reason to return.

A malformed key, an unknown public part and a wrong secret are refused alike, and an unknown public part is compared
against a fixed digest so it costs the same as a wrong secret. A refused key dispatches one `AuthenticationFailed` (flow
`api_key`, naming the key once one was found) and nothing else; an accepted key binds the owner and principal with the
key's scopes (`Auth::scopes()`) as an authentication, not a sign-in: only `Authenticated` and `PrincipalAssigned` fire,
with method `api_key`, the key's id in `credentialId` and its scopes. Keys carry no session and no refresh. The key's
last use is recorded at most once per `last_used_throttle_seconds`, with one conditional update. The guard counts no
attempts: a secret this long cannot be guessed, and a write per refused request would cost the hot path more than it
protects, so throttle the routes for that. A machine has no interactive sign-in: the guard's `attempt()` always fails
(`method_not_allowed`) and checks nothing. `Auth::guard('machine')->validate(['api_key' => $key])` says whether a key
would authenticate, binding and dispatching nothing.

### Tokens and keys on one route

A route may accept both a `jwt` guard's tokens and an `api_key` guard's keys, in either order (`auth:api,machine` or
`auth:machine,api`). Both arrive as `Authorization: Bearer`, so the package tells them apart by form: a credential
containing a `.` is a JWT (a compact JWS always has two), one without is an API key (a key never has one). On a route
whose `auth` middleware lists a guard of each kind, each guard reads only credentials of its own form and treats the
other's as no credential at all: it parses nothing, queries nothing and reports nothing. So a token that fails JWT
validation (a bad signature, the wrong `typ`, expired, the wrong `iss` or `aud`, another guard's, a segment missing or
extra, bad base64url) is reported once, as `AuthenticationFailed` with flow `bearer`, and never looked up as a key; a
refused key, or any other string without a dot, is reported once with flow `api_key` and never parsed as a token; and a
valid credential of either kind authenticates with no failure reported. A client credentials token is a JWT: it is its
`jwt` guard's alone, which holds it to its key by id on every request, never by a lookup of the key's public part.

Revocation is checked on every request either way: a key revoked between two requests is `credential_revoked` on the
second, and so is the next request with a client credentials token whose key was revoked.

The `auth` middleware (the package's, which the `auth` alias resolves to, or one of yours that extends it) records the
guards the route lists on the request before trying them, and the rule holds for every later ask in that request: on a
route listing both kinds, a controller's `Auth::guard('machine')->user()` with a JWT answers `null` and reports nothing,
since the JWT is not its own. A route listing one kind of guard, and a guard asked on a request the middleware did not
record (no `auth` middleware, or asked before it runs), reads every credential itself. A route listing two guards of one
kind (`auth:api,m2m`) gets one report from each guard that refuses the credential, each naming its guard: they are two
applications' refusals, not one.

Every other operation names the principal the key must belong to, and treats a key of another principal or guard as
absent, even one whose guard, type or identifier the column's collation counts as equal (`alice` and `Alice` under
MySQL's default `_ci` collations). These are privileged operations: authorise your caller to manage that principal's
keys first, since the package decides no permission.

```php
$keys = Auth::apiKeys('machine');

$keys->keys($principal);                       // list<ApiKeySummary>, newest first, revoked and rotated included
$keys->find($principal, $keyId);               // ?ApiKeySummary
$keys->revoke($principal, $keyId);             // whether this call revoked it; it stops working at once
$keys->rotate($principal, $keyId, overlapSeconds: 3600, expiresAt: now()->addYear()); // ?IssuedApiKey
```

A summary is safe to return from a route as it is: `toArray()` and its JSON use snake_case keys and ISO-8601 times, and
neither holds the secret or its digest.

Rotating issues a replacement with the same guard, owner, principal, tenant, name and scopes (held to the scope registry
again), but not the same expiry: the replacement expires at the `expiresAt` you pass, and never without one, so pass it
when you rotate a key that expires, or the replacement will not. The rotation ends the replaced key once the overlap
passes (`rotation_overlap_seconds` by default, at most `max_rotation_overlap_seconds`), or at its own expiry when that
comes sooner; both keys work during the overlap, and the replaced one then fails as `credential_expired`. Only a live
key that has not been rotated rotates: `null` otherwise, and of two concurrent rotations only one replaces the key. A
key's scopes are fixed for its life; to change them, issue a new key and revoke the old one. `ApiKeyIssued`,
`ApiKeyRotated` (with `previousKeyId`) and `ApiKeyRevoked` report each change once it is committed on the key's own
connection, never the key or its digest.

Schedule pruning of keys revoked or expired more than `prune_after_days` ago:

```php
$schedule->command('model:prune', ['--model' => [\SineMacula\Laravel\Authentication\Models\ApiKey::class]])->daily();
```

## Client credentials

The OAuth 2.0 client credentials grant (RFC 6749 section 4.4) exchanges a machine's API key for a short-lived access
token of a `jwt` guard. The key is issued on that guard (`Auth::apiKeys('m2m')->issue(...)`): its public part is the
OAuth `client_id` and its secret the `client_secret`, so a key is either presented to an `api_key` guard or exchanged on
a `jwt` guard, never both, and rotating a key gives its client a new id. The grant is off until an application lists
it in its `application.methods`:

```php
'm2m' => [
    'driver'      => 'jwt',
    'provider'    => 'clients',
    'application' => ['methods' => ['client_credentials']],
],
```

A client authenticates with HTTP Basic (`client_secret_basic`), which RFC 6749 section 2.3.1 requires every server to
accept. Credentials in the form body (`client_secret_post`), which RFC 6749 does not recommend, are accepted only where
the application sets `'client_secret_post' => true` beside its methods; otherwise they are refused as `invalid_client`,
before any query and without counting.

Routes stay yours; the exchange reads the request and answers in RFC 6749's shapes:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;

Route::post('/oauth/token', fn () => Auth::clientCredentials('m2m')->fromRequest());
```

`fromRequest()` reads a form-encoded POST: `grant_type=client_credentials`, an optional `scope` (space-separated), and
the client authenticated with HTTP Basic (`client_id:client_secret`, each form-url-encoded) or, where the application
allows it, with `client_id` and `client_secret` in the body, never both. A parameter in the query string, given twice or
not a string is refused rather than ignored, so a credential in a URL never works, and a parameter sent without a value
is treated as omitted (RFC 6749 section 3.1), so `grant_type=` names no grant and an empty `client_id` beside Basic is
no second authentication. `exchange($clientId, $clientSecret, $scope)` does the same for a client id and secret your
code read itself. The result is `Responsable`, answered with `Cache-Control: no-store` and `Pragma: no-cache`, or read
with `isGranted()`, `accessToken` (a `Secret`), `expiresIn`, `scopes`, `error` and `reason`. Its `toArray()` is the
response body alone with the token revealed, for a response you build yourself and must not let be stored; a granted
result encoded as JSON any other way (`json_encode()`, `response()->json()`) throws `SecretNotRevealedException` rather
than send the token without `no-store`, and a failed one encodes as its error body. Either way `reason`, which only your
code and the event should see, never reaches a client:

| Outcome                                                                                 | Response                       |
|-----------------------------------------------------------------------------------------|--------------------------------|
| Granted                                                                                 | 200, the token (below)         |
| Not a POST or not form-encoded; a parameter in the query, repeated or not a string      | 400 `invalid_request`          |
| No `grant_type`; Basic and body credentials together                                    | 400 `invalid_request`          |
| A `grant_type` other than `client_credentials`                                          | 400 `unsupported_grant_type`   |
| No client authentication, malformed Basic, an unknown client or a wrong secret          | 401 `invalid_client`           |
| Body credentials where the application does not set `client_secret_post`                | 401 `invalid_client`           |
| A revoked, expired or another guard's key; its owner unknown, not a machine or inactive | 401 `invalid_client`           |
| Its principal or tenant no longer the key's, or inactive                                | 401 `invalid_client`           |
| The application lacks `client_credentials`, or refuses the principal as ineligible      | 400 `unauthorized_client`      |
| A scope that is malformed or not granted to the key                                     | 400 `invalid_scope`            |
| The IP address (or, when you limit it, the client id) used up its failures              | 429 `slow_down`, `Retry-After` |

A granted response is `{"access_token": "...", "token_type": "Bearer", "expires_in": 900, "scope": "invoices:read"}`,
without `scope` when the token grants none (RFC 6749 has no empty scope value; the token's own `scope` claim is then
`""`), and never a `refresh_token`. Every `invalid_client` is a 401 with `WWW-Authenticate: Basic realm="<guard>"`,
however the client authenticated: a 401 always carries a challenge (RFC 7235 section 3.1), and Basic is the method every
client may use. An error body is `{"error": "<code>"}` alone: `error_description` is optional in RFC 6749 section 5.2,
and the package words nothing a client reads, so add one in your own response if you want it. A principal the
application policy refuses as `principal_ineligible` is `unauthorized_client`, and one it refuses for any other reason
`invalid_client`. `invalid_grant` is never answered: for this grant the client's own authentication is the grant, and a
failed one is `invalid_client`. `slow_down` is outside RFC 6749, which defines no rate-limit error: it is the package's
own answer to a client past its limit, with a code the OAuth registry holds (RFC 8628). Only failures to authenticate
the client count against the `client_credentials` limits (100 per IP address a minute by default), and each is answered
alike. Failures are not counted per client id by default: a client id is not a secret (RFC 6749 section 2.2), so a limit
on it would let anyone who knows it hold the real client back from any address, while against a 40-character random
secret it protects nothing. Set `rate_limits.client_credentials.per_identifier` only if you accept that. No scope asks
for every scope the key grants; otherwise the token grants exactly those asked for. Every failure dispatches
`AuthenticationFailed` (flow `client_credentials`, the client id when it is a key's public part in form, else none, so a
whole key or a secret sent as the id never reaches a listener, and the key once found) and a grant
`ClientCredentialsGranted`, with the key and the scopes granted.

RFC 6749 section 3.2 requires TLS on the token endpoint. That is the deployment's to enforce, since whether a request
arrived over TLS depends on your trusted proxies (`$request->isSecure()`); the exchange does not check it.

The token is an access token of the guard with no session: the client (the key's non-human identity) in `sub` with the
subject type `machine` in `sub_type`, the key's id in `cid` and its scopes in `scope`; it lives the guard's access
lifetime, never past the key's expiry, and no refresh token is issued. On every request the bearer path
reads its key by primary key (one query more than any session-less token) and requires it to be the guard's
(`credential_invalid`), not revoked (`credential_revoked`) and not expired (`credential_expired`); the subject must be a
machine (`credential_invalid`), and the key's owner, principal and tenant must still be what loaded
(`principal_mismatch`, `credential_invalid`). Revoking the key, or the end of its rotation's overlap, so ends its tokens
at the next request. A request with such a token binds with method `client_credentials`, the key in `credentialId` and
`Auth::scopes()` the token's scopes.
