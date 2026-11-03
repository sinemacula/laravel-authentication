# Events and failure outcomes

## Events

| Event                                             | Fired when                                                                                          |
|---------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| `Illuminate\Auth\Events\Attempting`               | A sign-in or refresh starts (never a bearer request)                                                |
| `Illuminate\Auth\Events\Validated`                | A sign-in or refresh is about to bind context                                                       |
| `Illuminate\Auth\Events\Authenticated`            | Identity bound to the guard, bearer requests included                                               |
| `Illuminate\Auth\Events\Login`                    | A sign-in or refresh bound the guard                                                                |
| `Illuminate\Auth\Events\Failed`                   | A sign-in or refresh was rejected (never a bearer token)                                            |
| `Illuminate\Auth\Events\Logout`                   | `logout()` or `signOut()` ended a signed-in request                                                 |
| `SineMacula\...\Events\PrincipalAssigned`         | Principal resolved and bound                                                                        |
| `SineMacula\...\Events\SessionAuthenticated`      | Session hydrated and bound; listeners may persist metadata                                          |
| `SineMacula\...\Events\Refreshed`                 | Refresh exchange completed, once committed                                                          |
| `SineMacula\...\Events\SessionRevoked`            | The package revoked a session, once committed; with reason                                          |
| `SineMacula\...\Events\SignedOutEverywhere`       | A bulk revocation ended a scope's sessions, once committed                                          |
| `SineMacula\...\Events\SessionCreated`            | The session service created a session, once committed                                               |
| `SineMacula\...\Events\SignedIn`                  | A session started or was refreshed, once committed                                                  |
| `SineMacula\...\Events\SessionPending`            | A sign-in's session waits on a further factor or a choice, once committed                           |
| `SineMacula\...\Events\SessionReturnedToPending`  | An active session returned to pending, once committed                                               |
| `SineMacula\...\Events\SessionActivated`          | A pending session that had been active activated again, once committed                              |
| `SineMacula\...\Events\PrincipalSwitched`         | A session switched its principal, its active tenant or both, once committed; with what changed      |
| `SineMacula\...\Events\SteppedUp`                 | A session recorded a further factor or recovery code, once committed; with kind and method          |
| `SineMacula\...\Events\Reauthenticated`           | A session was reauthenticated with its first factor, once committed                                 |
| `SineMacula\...\Events\IdentifierVerified`        | An identifier was verified (after commit); carries type                                             |
| `SineMacula\...\Events\PasswordSet`               | A password was set or reset, once committed; with flow                                              |
| `SineMacula\...\Events\IdentifierChangeRequested` | A change of identifier waits for its proof, once committed                                          |
| `SineMacula\...\Events\IdentifierChanged`         | An identifier was replaced by a proven one, once committed                                          |
| `SineMacula\...\Events\PasskeyAdded`              | A passkey was registered, once committed                                                            |
| `SineMacula\...\Events\PasskeyUsed`               | A passkey's assertion was verified, once committed                                                  |
| `SineMacula\...\Events\PasskeyRemoved`            | A passkey was removed, once committed                                                               |
| `SineMacula\...\Events\ApiKeyIssued`              | An API key was issued, once committed                                                               |
| `SineMacula\...\Events\ApiKeyRotated`             | An API key was rotated, once committed; previous key id                                             |
| `SineMacula\...\Events\ApiKeyRevoked`             | An API key was revoked, once committed                                                              |
| `SineMacula\...\Events\ClientCredentialsGranted`  | A client credentials exchange issued an access token                                                |
| `SineMacula\...\Events\ExternalResultRedeemed`    | An external result signed a session in or reauthenticated one, once committed; with connection      |
| `SineMacula\...\Events\ExternalResultUnlinked`    | An external result was linked to no identity; informational, never provisions                       |
| `SineMacula\...\Events\AuthenticationFailed`      | Any sign-in, refresh, switch, step-up, reauthentication, bearer, key, code, reset or change failure |

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
`$event->context` (also `$event->context()`), so one audit mapper takes them all and attributes each the same way. With
`laravel-iam` installed, it maps every `AuthenticationEvent` into `laravel-audit-log`, and there is nothing to wire.
Without it, register a mapper in a service provider's `boot()`:

```php
use SineMacula\Laravel\AuditLog\Facades\AuditLog;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;

AuditLog::map(AuthenticationEvent::class, AuthenticationAuditMapper::class);
```

The mapper gives each event an explicit, dotted code, never one derived from the class name (which changes on a
rename), fills the record from the context's snapshot, and returns it, or `null` to skip the event:

```php
use SineMacula\Laravel\AuditLog\Contracts\EventMapper;
use SineMacula\Laravel\AuditLog\Records\PendingRecord;
use SineMacula\Laravel\AuditLog\Records\Reference;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedIn;

final class AuthenticationAuditMapper implements EventMapper
{
    public function map(object $event, PendingRecord $record): ?PendingRecord
    {
        $code = match ($event::class) {
            SignedIn::class             => 'authentication.signed_in',
            SessionRevoked::class       => 'session.revoked',
            AuthenticationFailed::class => 'authentication.sign_in_failed',
            default                     => null,
        };

        if ($code === null) {
            return null;
        }

        $context = $event->context();

        $record->event($code)
            ->by(Reference::of($context->identityType, $context->identityId))
            ->asPrincipal(Reference::of($context->principalType, $context->principalId))
            ->forTenant(Reference::of($context->tenantType, $context->tenantId))
            ->usingCredential($context->credentialId)
            ->withProperties(['guard' => $context->guard, 'session' => $context->sessionId, 'method' => $context->method]);

        return $event instanceof AuthenticationFailed ? $record->failed($event->reason->value) : $record;
    }
}
```

Codes follow the audit log's vocabulary: `authentication.` for signing in, `session.` for what happens to a session
(`session.pending`, `session.returned_to_pending`, `session.activated`, `session.switched` for `PrincipalSwitched`). A
mapped event is recorded at once: the events that report a write are already dispatched after it commits.

The context is an allowlist of plain values, never a model: the guard, the client of the request being served (IP
address and user agent, cleaned as the session columns are), the identity, the principal and the tenant it acts within
each by morph class and identifier (`identityType` and `identityId`, `principalType` and `principalId`, `tenantType` and
`tenantId`; the morph class is an Eloquent model's `getMorphClass()`, else its class name, as it is for a model an
enforced morph map leaves out), the session's identifier (`sessionId`, which keeps the session id a token named even
when no session was found), the sign-in method (for a session's events, the method it records; for a step-up or a
reauthentication, the method that proved it, such as `totp` or `passkey`, whether it succeeded or failed), the
credential (an API key or a passkey) in `credentialId` with the scopes it grants in `scopes` (`null` for a human
identity's session, which no credential limits), when it happened (`occurredAt`), and, for what an external provider's
result was redeemed into, the connection (`connectionId`) and the authorisation request's public reference
(`requestReference`). As much as the event's flow established is named, and what it did not establish is `null`: a
failure names only as much as it got to, and the session before one exists has no identifier. An event about a session
row itself (every `SessionRevoked`, and a refresh or switch refused on the row's own state before its owner was read,
such as a revoked or ended session or a replay) names the owner and principal the row records in `identityType`,
`identityId`, `principalType` and `principalId` when the flow did not load them, and the active tenant the row records
(its `tenant_id`) in `tenantId`, with no `tenantType`, when the flow did not load the tenant. Other events name only what
they hold, even when they carry a session: an identity's `SignedOutEverywhere`, a `SessionPending` waiting on a choice
of principal and a switch refused for its target have no principal.

`toArray()` gives the context as scalars, with `occurred_at` as an ISO 8601 UTC string to the microsecond, ready to store
or to queue on its own. Since every package event holds plain values only, it crosses a queue as it is: restoring it
runs no query and never fails on a row that is gone (a pruned session, an erased account), and a queued listener gets
exactly what was dispatched. A listener that needs a model loads it itself, on the write connection, from the type and
identifier, and treats one that is gone as nothing to do, as the package's own listeners do. Laravel's own events
(`Attempting`, `Validated`, `Login`, `Authenticated`, `Failed`, `Logout`) are unchanged and keep their models. No event
carries a token, a digest, a password or any other secret. An event that reports a write is dispatched once the write is
committed on the written row's own connection: at once when it has no open transaction, on its commit otherwise, and
never when it is rolled back; a transaction on another connection neither delays nor withdraws it. It goes to the
dispatcher bound when it is dispatched, not the one bound at the write, so an `Event::fake()` made between the write and
its commit receives it, while what it reports is still taken at the write.

A request's bearer token authenticates; it is not a sign-in. It dispatches only Laravel's `Authenticated` and the
package's `PrincipalAssigned` and `SessionAuthenticated`, and a rejected token only `AuthenticationFailed`, once per
request: never `Attempting`, `Validated`, `Login` or `Failed`, so a listener on those records sign-ins, not requests. A
request without a token dispatches nothing.

`Login` and `SignedIn` report real sign-ins: a session the session service started (`signIn()`, `start()`,
`signInExternally()`, or `satisfy()` or `choose()` activating a pending session), with the method that proved who signed
in, and a refresh, which renews the session and dispatches `Refreshed` and then `SignedIn` with `$refresh` set and the
method the session records. `attempt()` starts no session and never dispatches `SignedIn`: Laravel's `Login` reports its
sign-ins, and code that calls `start()` after `attempt()` reports the sign-in once. `SessionCreated` precedes the
`SignedIn` of every sign-in that starts a session (not a refresh's, which keeps its session); a sign-in that proved the
client's previous session dispatches that session's `SessionRevoked` (`superseded`) before both. A sign-in whose session
is written pending (a further factor or a choice of principal outstanding) dispatches `SessionPending` instead, once
committed, with what it waits on and when its credential expires: from `signIn()` it answers the sign-in's `Attempting`,
and from `start()` and `signInExternally()`, which dispatch no `Attempting`, it is the only event. Its first activation
dispatches `SessionCreated` and `SignedIn` (with the superseded session's `SessionRevoked` first), and discarding it
`SessionRevoked` with `signed_out`. An external result redeemed into a session dispatches `ExternalResultRedeemed` once
committed, after the session's own events: flow `sign_in` for a `signInExternally()` that wrote a session, active or
pending (after its `SessionCreated` and `SignedIn`, or its `SessionPending`), and flow `reauthentication` for a
`reauthenticateExternally()` that issued a token (after its `Reauthenticated`); a rolled-back redemption dispatches
nothing. Its context carries the identity, principal, tenant and session as the redemption established them, the method
`external_provider`, the connection and the request reference, and so does every event of a refused redemption
(`AuthenticationFailed`, `ExternalResultUnlinked`), while the session's own events correlate with it by session id. An
external result linked to no identity dispatches `ExternalResultUnlinked` (the guard, the client, the connection and the
issuer, never the subject) and then the sign-in's `Failed` and `AuthenticationFailed` (`external_result_unlinked`); it
reports, and provisions nothing: the package that verified the result provisions on its own event, before it hands the
result over. A session that returns to pending from active dispatches `SessionReturnedToPending`, with the flow, what it
waits on and the principal and tenant it left when they changed, and its later activation `SessionActivated`, not
`SessionCreated` or `SignedIn`. A switch is no sign-in: it dispatches `PrincipalSwitched` when it changed the principal
or the active tenant (with which in `principalChanged` and `tenantChanged`, and the tenant left in `previousTenantId`),
or `SessionReturnedToPending` when its destination asks for a further factor, and no `Login` or `SignedIn`. Nor is a
step-up or a reauthentication, which keep their session: each dispatches `SteppedUp` or `Reauthenticated` once
committed, and a refusal `AuthenticationFailed`, never `Attempting`, `Failed`, `Login` or `SignedIn`. Nor is the factor
package's removal of a factor the current session relied on: when that leaves it short, `SessionReturnedToPending`
reports it with the flow `factor_change` (see [Sign-in factors](sessions.md#sign-in-factors)). The event that reports a
session's write (`SessionCreated`, `SignedIn`, `Refreshed` or `PrincipalSwitched`) is scheduled before the guard is
bound to the session, so a listener that throws on `Validated`, `Login`, `Authenticated`, `PrincipalAssigned` or
`SessionAuthenticated` cannot keep it from being reported (its exception still reaches the caller). Outside a
transaction it is therefore dispatched before those bind events: read the event's context in its listener, not the
guard, which may not be bound to the new session yet. The bind of a sign-in, a refresh or a switch itself waits for the
session's commit, so inside your transaction its bind events follow the commit, after the events that report the
session, and a rollback withdraws both.

Every refusal is reported once: a guard settles and reports its request's credential at most once (asking
`Auth::user()`, `Auth::context()`, `Auth::caller()` or `check()` again reports nothing more), each service call reports
its own refusal, and building the authentication context reports nothing. On a route whose `auth` middleware lists a
`jwt` and an `api_key` guard, a bearer credential is reported only by the guard its form belongs to, so a token that
fails is never reported again as a refused key: see
[Tokens and keys on one route](machine-credentials.md#tokens-and-keys-on-one-route). A route listing several guards of
one kind gets one report from each guard that refuses the credential, each naming its guard: they are different
applications' refusals, and are not merged.

`Auth::caller()` reports a refresh or pending credential the request carries and that is refused once per request, with
`AuthenticationFailed` alone: flow `refresh` with the reason a refresh would give (`additional_factor_required` for a
session a refresh would return to pending, and nothing revoked for `sso_required`), or flow `sign_in` with
`pending_invalid` or `pending_action_not_allowed`. It dispatches no `Attempting` and no `Failed`, since reading the
caller is not an attempt to authenticate, so a listener tells it from a refresh's own refusal by the transport, which
dispatches `Attempting`, `Failed` and `AuthenticationFailed` (see [Refreshing](refreshing.md)).

`AuthenticationFailed` reports every failed sign-in, refresh, switch, sign-out by refresh credential, step-up,
reauthentication, bearer token, API key, client credentials exchange, request for a one-time code, verification by code
or link, password reset request or submission, identifier change request or confirmation, factor code request or check,
and change or establishment of a password, after Laravel's `Failed` where that fires, with the flow
(`AuthenticationFlow`: `sign_in`, `refresh`, `bearer`, `switch`, `sign_out`, `step_up`, `reauthentication`, `api_key`,
`client_credentials`, `code_request`, `identifier_verification`, `password_reset`, `identifier_change`, `factor_code`,
`password_change`; see [Failure outcomes](#failure-outcomes) for what each answers), a `FailureReason`, the identifier a
sign-in's input named (as given), the wait for `rate_limited` and `account_rate_limited`, and the id of the challenge a
failed check answered (`challengeId`: a one-time code's checked as a sign-in, a factor, an identifier's verification or
change, or a password reset, and a passkey ceremony's signed in or reauthenticated with), when it is in the form the
package issues, which the further-factor package's own per-attempt events share; a sign-in or reauthentication refused
as `method_not_allowed` names none, since nothing was checked. Its context carries the identity only once a sign-in
method verified it, a refresh reloaded the session's owner or a token's subject was found (a wrong password or an
unknown identifier carries none), the principal and tenant once resolved, and the session once found, else the `sid` a
token named. A bearer token is checked in this order, so its reason is the first that applies:
`token_invalid`, for a client credentials token `credential_invalid`, `credential_revoked` and `credential_expired`,
then `identity_unknown`, `machine_identity`, `identity_inactive`, `principal_mismatch`, `principal_inactive`,
`tenant_inactive`, then for a token that names no session `issued_before_cutoff`, and for one that names a session
`session_unknown`, `session_guard_mismatch`, `session_revoked`, `session_pending`, `session_expired`,
`session_tenant_mismatch`, `session_principal_mismatch`, `session_switched`, and `tenant_inactive` for the session's
active tenant. It says why a sign-in failed even where the client is not told: a refusal by the account's own limit is
`account_rate_limited` on the event, while the sign-in's result says `invalid_credentials`:

| Reason                       | Meaning                                                                                             |
|------------------------------|-----------------------------------------------------------------------------------------------------|
| `invalid_credentials`        | The sign-in method did not accept the input                                                         |
| `method_not_allowed`         | The guard does not allow the sign-in method, or no longer the session's                             |
| `rate_limited`               | The identifier, session or IP address used up its attempts for now                                  |
| `account_rate_limited`       | The account used up its attempts; event only, not on the result                                     |
| `identity_unknown`           | The guard's provider does not return the identity or session owner                                  |
| `identity_inactive`          | The identity reported inactive                                                                      |
| `principal_unresolved`       | No principal could be resolved for the identity                                                     |
| `principal_mismatch`         | The requested principal (or a token's `principal`) is not the identity's                            |
| `principal_inactive`         | The principal reported inactive                                                                     |
| `tenant_inactive`            | The principal's or the active tenant inactive, or opted in and missing                              |
| `tenant_ineligible`          | The selected tenant does not resolve, or `TenantAccess` refuses it                                  |
| `principal_ineligible`       | `ApplicationAccess` does not let the principal use the application                                  |
| `sso_required`               | The tenant requires a session established through one of its connections                            |
| `identifier_unverified`      | The guard requires a verified identifier and it is not                                              |
| `session_mismatch`           | The pinned session is not a live session of the identity and principal                              |
| `additional_factor_required` | A further factor that `attempt()`, `Auth::caller()` or `reauthenticateExternally()` cannot wait for |
| `pending_invalid`            | The pending credential is unknown, expired, used, or not this guard's                               |
| `pending_action_not_allowed` | The pending session's first outstanding requirement does not allow the action                       |
| `session_pending`            | The session is pending: none of its tokens is accepted until it activates                           |
| `token_invalid`              | Decode, expiry, header type, `client_id`, `iss`, `aud`, missing or malformed claim                  |
| `issued_before_cutoff`       | Session-less token issued at or before a "tokens valid after" time                                  |
| `session_unknown`            | Session id is not a session key or names no session                                                 |
| `session_guard_mismatch`     | Session is another guard's (or none's); not revoked                                                 |
| `session_revoked`            | Session row marked revoked                                                                          |
| `session_expired`            | Session's idle or absolute deadline reached, or unset; a sign-in's deadline passed                  |
| `session_principal_mismatch` | Session acts as another principal than the token's                                                  |
| `session_tenant_mismatch`    | Session acts in another tenant than the token names                                                 |
| `session_switched`           | Session's principal or active tenant changed since the token's issue                                |
| `rotation_reuse`             | Rotated refresh token replayed; session revoked                                                     |
| `rotation_conflict`          | Session changed during the refresh; retry                                                           |
| `refresh_key_missing`        | Session holds no refresh credential                                                                 |
| `refresh_token_conflict`     | The request carried a refresh token in more than one carrier, or the cookie twice                   |
| `refresh_transport_mismatch` | The refresh token came by a carrier that is not the application's transport                         |
| `cross_site_request`         | A cookie refresh token without an allowed origin and the custom header                              |
| `code_expired`               | The one-time code expired; event only, not on a sign-in's result                                    |
| `code_exhausted`             | The code used up its attempts; event only, not on a sign-in's result                                |
| `passkey_challenge_invalid`  | The passkey challenge is unknown, expired, used, or another ceremony's                              |
| `passkey_counter_regressed`  | The passkey's sign counter did not advance; event only, not on result                               |
| `machine_identity`           | A non-human identity tried a sign-in, a session, a refresh or a switch                              |
| `credential_invalid`         | API key or client credential malformed, unknown, wrong, or not a machine's                          |
| `credential_revoked`         | The API key or client credential is revoked                                                         |
| `credential_expired`         | It expired, a rotated key's overlap included                                                        |
| `credential_guard_mismatch`  | It was issued for another guard                                                                     |
| `scope_invalid`              | A requested scope is malformed or not granted to the credential                                     |
| `reauthentication_required`  | An identifier change or a first factor without a fresh proof, or a wrong password                   |
| `identifier_taken`           | The new identifier is held by another identity, or the unique index refused it                      |
| `link_expired`               | A reset, change or verification link expired; event only, not on a reset's result                   |
| `proof_invalid`              | A further factor of a kind, purpose, evaluation or time the operation does not take                 |
| `proof_binding_mismatch`     | A further factor made by another identity, application or session                                   |
| `step_up_required`           | A factor change without a fresh step-up; on a `FactorChangeVerdict`, not an event                   |
| `deliveries_exhausted`       | The destination's delivery window has had all the code deliveries it allows                         |
| `factor_code_locked`         | The factor package has the factor or the identity locked against factor codes                       |
| `factor_code_refused`        | The factor package refused a factor code, or the outcome of an attempt at one                       |
| `password_not_set`           | A change of password for an identity that has none: establish one                                   |
| `password_already_set`       | A password to establish for an identity that has one: change it                                     |
| `external_result_unlinked`   | A result an external provider verified is linked to no identity                                     |
| `link_mismatch`              | Not established through the external result's link (or any), or the result names another link       |

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

| Flow                      | Entry points                                                                                                                                                            | The caller sees                                                                                                                                                                                                                                                                                                                                                                                                                             | Reasons on the event                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
|---------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `sign_in`                 | `attempt()`; `Auth::sessions()->signIn()`, `start()`, `signInExternally()`, `satisfy()`, `choose()`, `discard()`; `Auth::caller()` on an `authentication.pending` route | `attempt()`: `false`. The session service: a `SignInResult` whose `isFailed()`, `reason` and, for `rate_limited`, `retryAfter` say why; `discard()`: whether it discarded a pending session; `Auth::caller()`: `null`                                                                                                                                                                                                                       | `invalid_credentials`, `method_not_allowed`, `rate_limited`, `identity_unknown`, `identity_inactive`, `machine_identity`, `principal_unresolved`, `principal_mismatch`, `principal_inactive`, `tenant_inactive`, `tenant_ineligible`, `principal_ineligible`, `identifier_unverified`, `session_mismatch` and `additional_factor_required` (`attempt()`), `sso_required`, `pending_invalid`, `pending_action_not_allowed`, `session_expired` (a deadline the sign-in supplied had passed by the sign-in), `passkey_challenge_invalid`, `proof_invalid` and `proof_binding_mismatch` (`satisfy()`), `external_result_unlinked` and `link_mismatch` (`signInExternally()`); on the event only: `account_rate_limited`, `code_expired`, `code_exhausted`, `passkey_counter_regressed`                                |
| `bearer`                  | A request through `auth:<jwt guard>`, or `Auth::user()` and the accessors on one                                                                                        | `401 {"message": "Unauthenticated."}` from the `auth` middleware; `Auth::user()` is `null`                                                                                                                                                                                                                                                                                                                                                  | `token_invalid`, `credential_invalid`, `credential_revoked` and `credential_expired` (a client credentials token), `identity_unknown`, `machine_identity`, `identity_inactive`, `principal_mismatch`, `principal_inactive`, `tenant_inactive`, `issued_before_cutoff` (a token without a session), `session_unknown`, `session_guard_mismatch`, `session_revoked`, `session_pending`, `session_expired`, `session_tenant_mismatch`, `session_principal_mismatch`, `session_switched`                                                                                                                                                                                                                                                                                                                              |
| `refresh`                 | `Auth::sessions()->refreshFromRequest()`, `refresh()`; `Auth::caller()` on an `authentication.refresh` route                                                            | A `RefreshResult` whose `isFailed()`, `reason` and, for `rate_limited`, `retryAfter` say why, or whose `isPending()` says the session returned to pending, with its `pending` session and `credential` and no pair (`null` from `refreshFromRequest()` when the request carries no token); `Auth::caller()`: `null`                                                                                                                         | `token_invalid`, `refresh_token_conflict`, `refresh_transport_mismatch`, `cross_site_request`, `rate_limited`, `session_unknown`, `session_guard_mismatch`, `session_revoked`, `session_pending`, `session_expired`, `refresh_key_missing`, `rotation_reuse` (the session is revoked), `rotation_conflict`, `session_principal_mismatch`, `session_tenant_mismatch` (a switch to another tenant won the write), `identity_unknown`, `machine_identity`, `identity_inactive`, `principal_unresolved`, `principal_mismatch`, `principal_inactive`, `tenant_inactive`, `method_not_allowed`, `principal_ineligible`, `tenant_ineligible`, `sso_required` (a refresh revokes the session, `Auth::caller()` nothing), `additional_factor_required` (`Auth::caller()`, for a session a refresh would return to pending) |
| `switch`                  | `Auth::sessions()->switchFromRequest()`, `switchTo()`                                                                                                                   | A `SwitchResult` whose `isFailed()`, `reason` and, for `rate_limited`, `retryAfter` say why, or whose `isPending()` says the session returned to pending (`null` from `switchFromRequest()` when the request carries no token)                                                                                                                                                                                                              | Those of `refresh`, with `rate_limited` returned rather than thrown, and `sso_required` revoking nothing (the session is left as it was)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `sign_out`                | `Auth::sessions()->signOutFromRequest()`, `signOutWith()`                                                                                                               | A `SignOutResult` whose `isFailed()` and `reason` say why the refresh credential was refused; `signOutFromRequest()` signs the request out either way, `signOutWith()` forgets only a binding to the session it revoked, and a cookie application's result carries the expired cookie for a request its own pages sent                                                                                                                      | `token_invalid`, `refresh_token_conflict`, `refresh_transport_mismatch`, `cross_site_request`, `session_unknown`, `session_guard_mismatch`, `session_revoked`, `session_pending`, `session_expired`, `refresh_key_missing`, `rotation_reuse` (the session is revoked), `session_principal_mismatch`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `step_up`                 | `Auth::sessions()->stepUp()`                                                                                                                                            | An `AccessTokenResult` whose `isIssued()`, `accessToken` and `expiresAt` give the session's new access token, or whose `isFailed()` and `reason` say why (see [Stepping up](sessions.md#stepping-up))                                                                                                                                                                                                                                       | `proof_invalid`, `proof_binding_mismatch`, `session_unknown`, `session_guard_mismatch`, `session_revoked`, `session_pending`, `session_expired`, `machine_identity`, `session_principal_mismatch`, `identity_unknown`, `identity_inactive`, `principal_unresolved`, `principal_mismatch`, `principal_inactive`, `tenant_inactive`, `method_not_allowed`, `principal_ineligible`                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `reauthentication`        | `Auth::sessions()->reauthenticate()`, `reauthenticateExternally()`                                                                                                      | An `AccessTokenResult` as for a step-up, and for `rate_limited` its `retryAfter`; a concealed reason is `invalid_credentials`, with no wait (see [Reauthenticating](sessions.md#reauthenticating))                                                                                                                                                                                                                                          | `method_not_allowed`, `session_unknown`, `session_guard_mismatch`, `session_revoked`, `session_pending`, `session_expired`, `machine_identity`, `rate_limited`, `account_rate_limited`, `invalid_credentials` (another identity's credential included), `identifier_unverified`, `code_expired`, `code_exhausted`, `passkey_challenge_invalid`, `passkey_counter_regressed`, `session_principal_mismatch`, `identity_unknown`, `identity_inactive`, `principal_unresolved`, `principal_mismatch`, `principal_inactive`, `tenant_inactive`, `principal_ineligible`, `proof_invalid`, `external_result_unlinked`, `link_mismatch`, `sso_required` and `additional_factor_required` (`reauthenticateExternally()`)                                                                                                   |
| `api_key`                 | A request through `auth:<api_key guard>`                                                                                                                                | `401 {"message": "Unauthenticated."}` from the `auth` middleware; the guard's `attempt()` is `false` and reports `method_not_allowed` on the `sign_in` flow                                                                                                                                                                                                                                                                                 | `credential_invalid`, `credential_guard_mismatch`, `credential_revoked`, `credential_expired`, `method_not_allowed`, `identity_unknown`, `identity_inactive`, `principal_mismatch`, `principal_inactive`, `tenant_inactive`, `principal_ineligible`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `client_credentials`      | `Auth::clientCredentials()->fromRequest()`, `exchange()`                                                                                                                | A `ClientCredentialsResult` answering RFC 6749's `invalid_request`, `unsupported_grant_type`, `invalid_client`, `unauthorized_client`, `invalid_scope`, or `slow_down` (see [Client credentials](machine-credentials.md#client-credentials))                                                                                                                                                                                                | `invalid_credentials` (a request refused before a client was found), `method_not_allowed`, `rate_limited`, every reason of `api_key`, `scope_invalid`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| `code_request`            | `Auth::codes()->send()`, `sendVerification()`                                                                                                                           | A `CodeRequest` whose `status` is `sent` (with the `challengeId` the check names), `rate_limited` or `deliveries_exhausted` (each with `retryAfter`), `method_not_allowed` or `identifier_invalid`; the same for an identifier no one holds                                                                                                                                                                                                 | `method_not_allowed` (`send()`), `invalid_credentials` (the result's `identifier_invalid`), `rate_limited`, `deliveries_exhausted`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `identifier_verification` | `Auth::codes()->verify()`, `VerificationLinks::consume()`                                                                                                               | A code: a `LimitedOutcome` of a `VerificationOutcome`, `invalid`, `expired`, `exhausted` or `rate_limited` (with `retryAfter`), not concealed, since the caller holds the identity. A link: a `VerificationLinkOutcome`, `invalid` (one that says nothing of the account) or `expired`. Either answers `mismatch` when the identifier changed meanwhile (nothing reported)                                                                  | A code: `invalid_credentials`, `code_expired`, `code_exhausted`, `rate_limited`. A link: `invalid_credentials`, `link_expired`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `password_reset`          | `Auth::passwords()->sendResetLink()`, `sendResetCode()`, `reset()`, `resetWithCode()`                                                                                   | A request: a `CodeRequest` as for a code (`sent`, `rate_limited` or `deliveries_exhausted` with `retryAfter`, `method_not_allowed`, `identifier_invalid`), the same for an identifier no one holds. A reset: a `ResetResult` whose `status` is `reset`, `invalid`, `rate_limited` (with `retryAfter`) or `password_rejected` (with the `violations`, reported by no event) (see [Password reset](passwords.md#password-reset))              | A request: `method_not_allowed`, `invalid_credentials` (the result's `identifier_invalid`), `rate_limited`, `deliveries_exhausted`. A reset: `rate_limited`, `invalid_credentials`, `machine_identity`, `identity_inactive`, `identifier_unverified`; on the event only: `code_expired`, `code_exhausted`, `link_expired`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `identifier_change`       | `Auth::identifierChanges()->requestByCode()`, `requestByLink()`, `confirmByCode()`, `confirmByLink()`                                                                   | A request: an `IdentifierChangeRequest` whose `status` is `sent`, `rate_limited` (with `retryAfter`), `reauthentication_required`, `identifier_invalid` or `identifier_unchanged`. A confirmation: a `LimitedOutcome` of an `IdentifierChangeOutcome`, `changed`, `invalid`, `expired`, `exhausted`, `taken` or `rate_limited` (with `retryAfter`; see [Changing identifiers](identifier-changes.md))                                       | `reauthentication_required`, `rate_limited`, `invalid_credentials` (an invalid or unchanged identifier, a wrong code or link, a change replaced or lost), `code_expired`, `link_expired`, `code_exhausted`, `identifier_taken`, `identity_inactive` (a confirmation for an identity that is not active), none of them concealed                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `factor_code`             | `Auth::codes()->sendFactorCode()`, `verifyFactorCode()`                                                                                                                 | A send: a `CodeRequest` whose `status` is `sent` (with the `challengeId`), `rate_limited` or `deliveries_exhausted` (with `retryAfter`), `locked` (with `lockedUntil` when the factor package said) or `refused` (with the factor package's `refusal`). A check: a `FactorCodeCheck` whose `outcome` is `verified`, `invalid`, `expired`, `exhausted`, `locked`, `refused` or `rate_limited`, not concealed (see [Extending](extending.md)) | `rate_limited`, `deliveries_exhausted`, `factor_code_locked`, `factor_code_refused`, `invalid_credentials`, `code_expired`, `code_exhausted`; the factor package reports its own per-attempt events                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| `password_change`         | `Auth::passwords()->change()`, `establish()`                                                                                                                            | A `PasswordResult` whose `reason` says why it was refused, and for `rate_limited` its `retryAfter`; a password the policy rejects carries its `violations` and is reported by no event (see [Changing or establishing a password](passwords.md#changing-or-establishing-a-password))                                                                                                                                                        | `session_unknown`, `session_guard_mismatch`, `session_revoked`, `session_pending`, `session_expired`, `machine_identity`, `identity_unknown`, `password_not_set`, `rate_limited`, `invalid_credentials` (a wrong current password, or a password written meanwhile), `password_already_set`, `reauthentication_required`, none of them concealed                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |

The concealed reasons (`FailureReason::isConcealed()`: `account_rate_limited`, `code_expired`, `code_exhausted`,
`link_expired` and `passkey_counter_regressed`) reach only the event in a sign-in, a reauthentication and a password
reset: their results say `invalid_credentials` and `invalid`, with no wait, so the answer reveals neither that an
account exists nor that a code or link was requested for it. The flows whose caller already holds the identity,
verification by code and an identifier change, tell the caller (an `expired` or `exhausted` outcome), as
`Auth::passkeys()->verifyFactor()` does with its `PasskeyFactorResult`'s `reason` (`passkey_counter_regressed`
included), which no event reports: the factor's outcome is the further-factor package's to report. A verification link
tells it too (`expired`): its expiry is read from the signed link before any identity is, so the answer says only that
the link was authentic, and every other refusal is `invalid`. A sign-in method may answer only `invalid_credentials`,
`identifier_unverified`, `code_expired`, `code_exhausted`, `passkey_challenge_invalid` and `passkey_counter_regressed`
(`FailureReason::isSignInMethodReason()`); every other reason is the session service's to give.
