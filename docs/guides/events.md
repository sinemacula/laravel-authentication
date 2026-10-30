# Events and failure outcomes

## Events

| Event                                             | Fired when                                                               |
|---------------------------------------------------|--------------------------------------------------------------------------|
| `Illuminate\Auth\Events\Attempting`               | A sign-in or refresh starts (never a bearer request)                     |
| `Illuminate\Auth\Events\Validated`                | A sign-in or refresh is about to bind context                            |
| `Illuminate\Auth\Events\Authenticated`            | Identity bound to the guard, bearer requests included                    |
| `Illuminate\Auth\Events\Login`                    | A sign-in or refresh bound the guard                                     |
| `Illuminate\Auth\Events\Failed`                   | A sign-in or refresh was rejected (never a bearer token)                 |
| `Illuminate\Auth\Events\Logout`                   | `logout()` or `signOut()` ended a signed-in request                      |
| `SineMacula\...\Events\PrincipalAssigned`         | Principal resolved and bound                                             |
| `SineMacula\...\Events\DeviceAuthenticated`       | Device hydrated and bound; listeners may persist metadata                |
| `SineMacula\...\Events\Refreshed`                 | Refresh exchange completed, once committed                               |
| `SineMacula\...\Events\DeviceRevoked`             | The package revoked a device, once committed; with reason                |
| `SineMacula\...\Events\SignedOutEverywhere`       | A bulk revocation ended a scope's sessions, once committed               |
| `SineMacula\...\Events\DeviceCreated`             | The session service created a device, once committed                     |
| `SineMacula\...\Events\SignedIn`                  | A session started or was refreshed, once committed                       |
| `SineMacula\...\Events\AdditionalFactorRequired`  | A sign-in waits for a further factor, once committed                     |
| `SineMacula\...\Events\PrincipalChoiceRequired`   | A sign-in waits for a choice of principal, once committed                |
| `SineMacula\...\Events\PrincipalSwitched`         | A session switched its principal, once committed                         |
| `SineMacula\...\Events\IdentifierVerified`        | An identifier was verified (after commit); carries type                  |
| `SineMacula\...\Events\PasswordSet`               | A password was set or reset, once committed; with flow                   |
| `SineMacula\...\Events\IdentifierChangeRequested` | A change of identifier waits for its proof, once committed               |
| `SineMacula\...\Events\IdentifierChanged`         | An identifier was replaced by a proven one, once committed               |
| `SineMacula\...\Events\PasskeyAdded`              | A passkey was registered, once committed                                 |
| `SineMacula\...\Events\PasskeyUsed`               | A passkey's assertion was verified, once committed                       |
| `SineMacula\...\Events\PasskeyRemoved`            | A passkey was removed, once committed                                    |
| `SineMacula\...\Events\ApiKeyIssued`              | An API key was issued, once committed                                    |
| `SineMacula\...\Events\ApiKeyRotated`             | An API key was rotated, once committed; previous key id                  |
| `SineMacula\...\Events\ApiKeyRevoked`             | An API key was revoked, once committed                                   |
| `SineMacula\...\Events\ClientCredentialsGranted`  | A client credentials exchange issued an access token                     |
| `SineMacula\...\Events\AuthenticationFailed`      | Any sign-in, refresh, switch, bearer, key, code, reset or change failure |

The credentials on `Attempting` and `Failed` never include a password: every key whose name contains `password`
(case-insensitive), such as `password`, `current_password`, or `password_confirmation`, is removed before the event is
dispatched, and the identifier is kept for throttling and audit listeners. To remove more keys, list name fragments in
the published config:

```php
'events' => [
    'redacted_credential_keys' => ['secret', 'code'],
],
```

Every package event implements `SineMacula\...\Contracts\AuthenticationEvent` and carries one `EventContext` in
`$event->context` (also `$event->context()`), so one listener takes them all and attributes each the same way:

```php
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;

Event::listen(AuthenticationEvent::class, function (AuthenticationEvent $event): void {
    $context = $event->context();

    AuditLog::record(
        event: $event::class,
        guard: $context->guard,
        identity: $context->identityId,
        principal: [$context->principalType, $context->principalId],
        tenant: $context->tenantId,
        device: $context->deviceId,
        method: $context->method,
        credential: $context->credentialId,
        scopes: $context->scopes,
        ip: $context->client->ip,
        userAgent: $context->client->userAgent,
    );
});
```

The context holds the guard, the client of the request being served (IP address and user agent, cleaned as the device
columns are), and as much as the event's flow established of the identity, the principal, the tenant it acts within, the
device and the sign-in method (for a device's events, the method its session records), and the credential (an API key or
a passkey) in `credentialId` with the scopes it grants in `scopes` (`null` for a human identity's session, which no
credential limits); what was not established is `null`. It also snapshots, when the event is built, the identity's auth
identifier (`identityId`), the principal's recorded type and identifier (`principalType`, `principalId`), and the
tenant's and the device's identifiers (`tenantId`, `deviceId`, which keeps the device id a token named even when no
device was found). An event about a device row itself (every `DeviceRevoked`, and a refresh or switch refused on the
row's own state before its owner was read, such as a revoked or ended device or a replay) names the owner and principal
the row records in `identityId`, `principalType` and `principalId` when the flow did not load them; a device records no
tenant, so a revocation's `tenantId` is known only when the tenant's deactivation or the request's own session is why.
Other events name only what they hold, even when they carry a device: an identity's `SignedOutEverywhere`,
`PrincipalChoiceRequired` and a switch refused for its target have no principal. The snapshots, the client, the method
and the other values are fixed facts that survive a queue unchanged. The models are live references: a synchronous
listener gets the package's own instances, and a queued listener gets them re-fetched in their state when it runs, as
Laravel's `SerializesModels` does, or a `ModelNotFoundException` when one was deleted meanwhile (a pruned device, say).
Audit sinks should record the snapshots. No event carries a token, a digest, a password or any other secret. An event
that reports a write is dispatched once the write is committed on the written row's own connection: at once when it has
no open transaction, on its commit otherwise, and never when it is rolled back; a transaction on another connection
neither delays nor withdraws it.

A request's bearer token authenticates; it is not a sign-in. It dispatches only Laravel's `Authenticated` and the
package's `PrincipalAssigned` and `DeviceAuthenticated`, and a rejected token only `AuthenticationFailed`, once per
request: never `Attempting`, `Validated`, `Login` or `Failed`, so a listener on those records sign-ins, not requests. A
request without a token dispatches nothing.

`Login` and `SignedIn` report real sign-ins: a session the session service started (`signIn()`, `start()` or
`complete()`), with the method that proved who signed in, and a refresh, which renews the session on its device and
dispatches `Refreshed` and then `SignedIn` with `$refresh` set and the method the device's session records. `attempt()`
starts no session and never dispatches `SignedIn`: Laravel's `Login` reports its sign-ins, and code that calls `start()`
after `attempt()` reports the sign-in once. `DeviceCreated` precedes `SignedIn` for a new device
(`SignedIn::$deviceCreated`). A sign-in the additional-factor policy holds for a further factor dispatches
`AdditionalFactorRequired` instead, once committed: from `signIn()` it answers the sign-in's `Attempting`, and from
`start()`, which dispatches no `Attempting`, it is the only event. Completing it dispatches `SignedIn`, and discarding
it `AuthenticationFailed` with `additional_factor_failed`. A sign-in that waits for a choice of principal dispatches
`PrincipalChoiceRequired` the same way; choosing starts the session (or a pending factor) as above, and discarding the
choice dispatches `AuthenticationFailed` with `principal_choice_abandoned`. A switch of principal is no sign-in: it
dispatches `PrincipalSwitched`, and no `Login` or `SignedIn`.

`AuthenticationFailed` reports every failed sign-in, refresh, switch of principal, bearer token, API key, client
credentials exchange, request for a one-time code, verification by code, password reset request or submission, and
identifier change request or confirmation, after Laravel's `Failed` where that fires, with the flow
(`AuthenticationFlow`: `sign_in`, `refresh`, `bearer`, `principal_switch`, `api_key`, `client_credentials`,
`code_request`, `identifier_verification`, `password_reset`, `identifier_change`; see [Failure
outcomes](#failure-outcomes) for what each answers), a `FailureReason`, the identifier a sign-in's input named (as
given), and the wait for `rate_limited` and `account_rate_limited`. Its context carries the identity only once a sign-in
method verified it, a refresh reloaded the device's owner or a token's subject was found (a wrong password or an unknown
identifier carries none), the principal and tenant once resolved, and the device once found, else the `did` a token
named. A bearer token is checked in this order, so its reason is the first that applies: `token_invalid`, for a client
credentials token `credential_invalid`, `credential_revoked` and `credential_expired`, then `identity_unknown`,
`machine_identity`, `identity_inactive`, `principal_mismatch`, `principal_inactive`, `tenant_inactive`, then for a token
that names no device `issued_before_cutoff`, and for one that names a device `device_unknown`, `device_guard_mismatch`,
`device_revoked`, `session_expired`, `device_principal_mismatch`. It says why a sign-in failed even where the client is
not told: a refusal by the account's own limit is `account_rate_limited` on the event, while the sign-in's result says
`invalid_credentials`:

| Reason                       | Meaning                                                                           |
|------------------------------|-----------------------------------------------------------------------------------|
| `invalid_credentials`        | The sign-in method did not accept the input                                       |
| `method_not_allowed`         | The guard does not allow the sign-in method, or no longer the session's           |
| `rate_limited`               | The identifier, device or IP address used up its attempts for now                 |
| `account_rate_limited`       | The account used up its attempts; event only, not on the result                   |
| `identity_unknown`           | The guard's provider does not return the identity or device owner                 |
| `identity_inactive`          | The identity reported inactive                                                    |
| `principal_unresolved`       | No principal could be resolved for the identity                                   |
| `principal_mismatch`         | The requested principal (or a token's `pid`) is not the identity's                |
| `principal_inactive`         | The principal reported inactive                                                   |
| `tenant_inactive`            | The principal's tenant inactive, or opted in and missing                          |
| `principal_ineligible`       | The guard's audience policy does not admit the identity as principal              |
| `identifier_unverified`      | The guard requires a verified identifier and it is not                            |
| `device_mismatch`            | The pinned device is not a live device of the identity and principal              |
| `additional_factor_required` | A further factor is required, which only `signIn()` can ask                       |
| `additional_factor_failed`   | A pending sign-in was discarded: its further factor failed                        |
| `principal_choice_abandoned` | A choice of principal was discarded                                               |
| `pending_invalid`            | The pending sign-in is unknown, expired, used, or not this guard's                |
| `token_invalid`              | Decode, expiry, missing claim, typ, guard, iss, aud                               |
| `issued_before_cutoff`       | Device-less token issued at or before a "tokens valid after" time                 |
| `device_unknown`             | Device id is not a device key or names no device                                  |
| `device_guard_mismatch`      | Device is another guard's (or none's); not revoked                                |
| `device_revoked`             | Device row marked revoked                                                         |
| `session_expired`            | Device's idle or absolute deadline reached, or unset                              |
| `device_principal_mismatch`  | Device acts as another principal, or switched since the token's issue             |
| `rotation_reuse`             | Rotated refresh token replayed; device revoked                                    |
| `rotation_conflict`          | Device changed during the refresh; retry                                          |
| `refresh_key_missing`        | Device holds no refresh credential                                                |
| `refresh_token_conflict`     | The request carried a refresh token in more than one source                       |
| `cross_site_request`         | A cookie refresh token without an allowed origin and the custom header            |
| `code_expired`               | The one-time code expired; event only, not on a sign-in's result                  |
| `code_exhausted`             | The code used up its attempts; event only, not on a sign-in's result              |
| `passkey_challenge_invalid`  | The passkey challenge is unknown, expired, used, or another ceremony's            |
| `passkey_counter_regressed`  | The passkey's sign counter did not advance; event only, not on result             |
| `machine_identity`           | A non-human identity tried a sign-in, a session, a refresh or a switch            |
| `credential_invalid`         | API key or client credential malformed, unknown, wrong, or not a machine's        |
| `credential_revoked`         | The API key or client credential is revoked                                       |
| `credential_expired`         | It expired, a rotated key's overlap included                                      |
| `credential_guard_mismatch`  | It was issued for another guard                                                   |
| `scope_invalid`              | A requested scope is malformed or not granted to the credential                   |
| `reauthentication_required`  | An identifier change without a recent authentication, or with a wrong password    |
| `identifier_taken`           | The new identifier is held by another identity, or the unique index refused it    |
| `link_expired`               | The reset or change link's token has expired; event only, not on a reset's result |

A sign-in method may answer only `invalid_credentials`, `identifier_unverified` (once its input proved possession of the
identifier), `code_expired`, `code_exhausted`, `passkey_challenge_invalid` and `passkey_counter_regressed`; every other
reason is the session service's to give. `account_rate_limited`, `code_expired`, `code_exhausted` and
`passkey_counter_regressed` are on the event only: the sign-in's result says `invalid_credentials`. A code request
refused because its number is not one is reported as `invalid_credentials`, while its result says `identifier_invalid`.

## Failure outcomes

A refused sign-in, request, refresh or exchange is a result, never an exception: the caller gets what the flow's API
returns, and `AuthenticationFailed` reports it with the flow (`$event->flow`), a `FailureReason` (`$event->reason`) and
the context. Exceptions are for misconfiguration (an `InvalidArgumentException` or a `LogicException` naming the setting
or the model) and for server errors, such as a database error, which propagate. What each flow answers, and the
reasons its event can carry (each reason's meaning is in [Events](#events)):

| Flow                      | Entry points                                                                                          | The caller sees                                                                                                                                                                                                                                                                                                                                                                                      | Reasons on the event                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
|---------------------------|-------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `sign_in`                 | `attempt()`; `Auth::sessions()->signIn()`, `start()`, `complete()`, `choose()`, `discard()`           | `attempt()`: `false`. The session service: a `SignInResult` whose `isFailed()`, `reason` and, for `rate_limited`, `retryAfter` say why; `discard()`: whether it discarded a pending sign-in                                                                                                                                                                                                          | `invalid_credentials`, `method_not_allowed`, `rate_limited`, `identity_unknown`, `identity_inactive`, `machine_identity`, `principal_unresolved`, `principal_mismatch`, `principal_inactive`, `tenant_inactive`, `principal_ineligible`, `identifier_unverified`, `device_mismatch` and `additional_factor_required` (`attempt()`), `additional_factor_failed`, `principal_choice_abandoned`, `pending_invalid`, `passkey_challenge_invalid`; on the event only: `account_rate_limited`, `code_expired`, `code_exhausted`, `passkey_counter_regressed` |
| `bearer`                  | A request through `auth:<jwt guard>`, or `Auth::user()` and the accessors on one                      | `401 {"message": "Unauthenticated."}` from the `auth` middleware; `Auth::user()` is `null`                                                                                                                                                                                                                                                                                                           | `token_invalid`, `credential_invalid`, `credential_revoked` and `credential_expired` (a client credentials token), `identity_unknown`, `machine_identity`, `identity_inactive`, `principal_mismatch`, `principal_inactive`, `tenant_inactive`, `issued_before_cutoff` (a token without a device), `device_unknown`, `device_guard_mismatch`, `device_revoked`, `session_expired`, `device_principal_mismatch`                                                                                                                                          |
| `refresh`                 | `refreshFromRequest()`, `refresh()`                                                                   | `refreshFromRequest()`: the `FailureReason` (`null` when the request carries no token); `refresh()`: `null`; `rate_limited`: a `ThrottleRequestsException`, 429 with `Retry-After`                                                                                                                                                                                                                   | `token_invalid`, `refresh_token_conflict`, `cross_site_request`, `rate_limited`, `device_unknown`, `device_guard_mismatch`, `device_revoked`, `session_expired`, `refresh_key_missing`, `rotation_reuse` (the device is revoked), `rotation_conflict`, `device_principal_mismatch`, `identity_unknown`, `machine_identity`, `identity_inactive`, `principal_unresolved`, `principal_mismatch`, `principal_inactive`, `tenant_inactive`, `method_not_allowed`, `principal_ineligible`                                                                   |
| `principal_switch`        | `Auth::sessions()->switchPrincipalFromRequest()`, `switchPrincipal()`                                 | A `SwitchResult` whose `isFailed()`, `reason` and, for `rate_limited`, `retryAfter` say why (`null` from `switchPrincipalFromRequest()` when the request carries no token)                                                                                                                                                                                                                           | Those of `refresh`, with `rate_limited` returned rather than thrown, and `additional_factor_required`                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| `api_key`                 | A request through `auth:<api_key guard>`                                                              | `401 {"message": "Unauthenticated."}` from the `auth` middleware; the guard's `attempt()` is `false` and reports `method_not_allowed` on the `sign_in` flow                                                                                                                                                                                                                                          | `credential_invalid`, `credential_guard_mismatch`, `credential_revoked`, `credential_expired`, `method_not_allowed`, `identity_unknown`, `identity_inactive`, `principal_mismatch`, `principal_inactive`, `tenant_inactive`, `principal_ineligible`                                                                                                                                                                                                                                                                                                    |
| `client_credentials`      | `Auth::clientCredentials()->fromRequest()`, `exchange()`                                              | A `ClientCredentialsResult` answering RFC 6749's `invalid_request`, `unsupported_grant_type`, `invalid_client`, `unauthorized_client`, `invalid_scope`, or `slow_down` (see [Client credentials](machine-credentials.md#client-credentials))                                                                                                                                                         | `invalid_credentials` (a request refused before a client was found), `method_not_allowed`, `rate_limited`, every reason of `api_key`, `scope_invalid`                                                                                                                                                                                                                                                                                                                                                                                                  |
| `code_request`            | `Auth::codes()->send()`, `sendVerification()`                                                         | A `CodeRequest` whose `status` is `sent`, `rate_limited` (with `retryAfter`), `method_not_allowed` or `identifier_invalid`; the same for an identifier no one holds                                                                                                                                                                                                                                  | `method_not_allowed` (`send()`), `invalid_credentials` (the result's `identifier_invalid`), `rate_limited`                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `identifier_verification` | `Auth::codes()->verify()`                                                                             | The `FailureReason` itself, since the caller holds the identity, or `IdentifierVerification::MISMATCH` when the identifier changed meanwhile (nothing reported)                                                                                                                                                                                                                                      | `invalid_credentials`, `code_expired`, `code_exhausted`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `password_reset`          | `Auth::passwords()->sendResetLink()`, `sendResetCode()`, `reset()`, `resetWithCode()`                 | A request: a `CodeRequest` as for a code (`sent`, `rate_limited` with `retryAfter`, `method_not_allowed`, `identifier_invalid`), the same for an identifier no one holds. A reset: a `ResetResult` whose `status` is `reset`, `invalid`, `rate_limited` (with `retryAfter`) or `password_rejected` (with the `violations`, reported by no event) (see [Password reset](passwords.md#password-reset)) | A request: `method_not_allowed`, `invalid_credentials` (the result's `identifier_invalid`), `rate_limited`. A reset: `rate_limited`, `invalid_credentials`, `machine_identity`, `identity_inactive`, `identifier_unverified`; on the event only: `code_expired`, `code_exhausted`, `link_expired`                                                                                                                                                                                                                                                      |
| `identifier_change`       | `Auth::identifierChanges()->requestByCode()`, `requestByLink()`, `confirmByCode()`, `confirmByLink()` | A request: an `IdentifierChangeRequest` whose `status` is `sent`, `rate_limited` (with `retryAfter`), `reauthentication_required`, `identifier_invalid` or `identifier_unchanged`. A confirmation: an `IdentifierChangeOutcome`, `changed`, `invalid`, `expired`, `exhausted` or `taken` (see [Changing identifiers](identifier-changes.md))                                                         | `reauthentication_required`, `rate_limited`, `invalid_credentials` (an invalid or unchanged identifier, a wrong code or link, a change replaced or lost), `code_expired`, `link_expired`, `code_exhausted`, `identifier_taken`, `identity_inactive` (a confirmation for an identity that is not active), none of them concealed                                                                                                                                                                                                                        |

The concealed reasons (`FailureReason::isConcealed()`: `account_rate_limited`, `code_expired`, `code_exhausted`,
`link_expired` and `passkey_counter_regressed`) reach only the event in a sign-in and a password reset: their results
say `invalid_credentials` and `invalid`, with no wait, so the answer reveals neither that an account exists nor that a
code or link was requested for it. The flows whose caller already holds the identity, verification by code and an
identifier change, tell the caller (`code_expired`, an `expired` or `exhausted` outcome). A sign-in method may answer
only `invalid_credentials`, `identifier_unverified`, `code_expired`, `code_exhausted`, `passkey_challenge_invalid` and
`passkey_counter_regressed` (`FailureReason::isSignInMethodReason()`); every other reason is the session service's to
give.
