# Event Model

## Purpose

This note records what a package event is: the context every one carries, what survives a queue, when an event that
reports a write is dispatched, and how failures are reported. Audit sinks, SIEM forwarders and lockout notices attach
to these events, so the shape and the timing are a contract.

## Invariants

- Every event the package dispatches implements `Contracts\AuthenticationEvent` and carries one `Events\EventContext`
  (`context()` returns it), so one listener on the contract receives them all. Laravel's own auth events (`Attempting`,
  `Validated`, `Login`, `Authenticated`, `Failed`, `Logout`) do not.
- A context holds the guard (`null` only for a device that records none), the client of the request being served (IP
  address and user agent, cleaned by `ClientContext`), and, as far as the flow established them, the identity, the
  principal, the tenant it acts within, the device, and the sign-in method (for a device's events, the method its
  session records). Where a credential is involved it also holds the credential's id (`credentialId`: an API key's or a
  passkey's id) and the scopes it grants (`scopes`: the granted list for an API key or a client credentials token, `[]`
  for a machine bound without one, `null` for a human identity's session). A part that was not established is `null`.
- A context snapshots, when it is built, the identity's auth identifier, the principal's recorded type (its morph class,
  or its class name) and identifier, the tenant's identifier and the device's identifier, all as strings. A device id a
  token named is kept as the device snapshot when no device row was loaded.
- An event about a device row itself is built with `fromDevice`: every `DeviceRevoked`, and a refresh or switch refused
  on the row's own state before its owner was read (a `RefreshJudgement` verdict, `identity_unknown`, a row that
  changed under the compare-and-swap). An identity or principal it does not hold then takes the snapshot of the owner
  and the principal the row records, read from its attributes without a query; devices record no tenant. Every other
  event keeps the snapshots of what it holds, even when it carries a device: an identity's `SignedOutEverywhere` (its
  device is the one kept), `PrincipalChoiceRequired` (the proven device) and a switch refused for its target name no
  principal.
- The snapshots, the credential's id and scopes, the enums, the client and the other strings are facts fixed at event
  time and survive a queue unchanged. The models are live references: a synchronous listener gets the instances the
  package holds, and a queued listener gets them re-fetched in their state when it runs, or Laravel's
  `ModelNotFoundException` when one was deleted meanwhile (a pruned device, say). Audit sinks should record the
  snapshots.
- No event field carries a token, a digest, a password, a pending credential or any other secret. The device's digests
  are hidden from its serialisation; like Laravel's own auth events, the live identity model holds its attributes.
- An event that reports a write is dispatched through `Database\AfterCommit` on the written row's connection: at once
  when that connection has no open transaction, on its commit otherwise, and never on rollback. No package event
  implements `ShouldDispatchAfterCommit`, which would defer it to the last transaction of any connection. Events that
  report an in-memory bind (`PrincipalAssigned`, `DeviceAuthenticated`) fire at once.
- A bind sets the identity, principal and device first and then dispatches `Authenticated`, `PrincipalAssigned` and
  `DeviceAuthenticated?`, all describing the same context, so a listener on any of them reads the whole of it from the
  guard. A bind the guard verified (bearer, refresh, `attempt()`, the session service) reports the tenant its activity
  check loaded; a trusted bind (`login()`, `authenticateAs()`, `setUser()`, `setPrincipal()`, `setDevice()`) reads the
  principal's tenant on the write connection and reports none when the tenant cannot be loaded
  (`TenantUnavailableException`), while a principal loaded without its tenant's key is a misconfiguration whose
  `LogicException` propagates.
- One failure event, `AuthenticationFailed`, reports every failed sign-in, refresh, principal switch, bearer token, API
  key, client credentials exchange, request for a one-time code and verification by code, with the flow
  (`AuthenticationFlow`) and a reason (`FailureReason`), the identifier a sign-in named, and the wait of a rate-limited
  failure. Where Laravel's `Failed` fires as well, it fires first and `AuthenticationFailed` second; a bearer token or
  an API key fires neither `Attempting` nor `Failed`, and its failure at most once per request.
- A sign-in method may refuse only with a sign-in method reason (`FailureReason::isSignInMethodReason()`:
  `invalid_credentials`, `identifier_unverified` once its input proved the identifier is held, `code_expired`,
  `code_exhausted`, `passkey_challenge_invalid` and `passkey_counter_regressed`); any other reason is the session
  service's to give, and a method that returns one is a misconfiguration (`LogicException`). A concealed reason
  (`FailureReason::isConcealed()`: `account_rate_limited`, `code_expired`, `code_exhausted`,
  `passkey_counter_regressed`) reaches only the event: `SignInResult::failed()` answers it as `invalid_credentials`,
  with no wait, so the client learns nothing a guess could use.
- `RefreshTokenExchange::exchange()` returns its `AuthenticationFailed` undispatched and its caller (the guard)
  dispatches it; the exchange itself dispatches only `DeviceRevoked`, after commit.

## Success Path

- Sign-in: the session service builds one context for a written session (guard, client, identity, principal, the tenant
  admission loaded, device, method) and dispatches `DeviceCreated` (new devices) and `SignedIn` with it after the
  device's connection commits, scheduling them before it binds the guard. A sign-in held for a factor dispatches
  `AdditionalFactorRequired` with the proven device, after the pending sign-in commits, and one held for a choice of
  principal `PrincipalChoiceRequired`, with the identity, the method and the proven device but no principal or tenant.
- Switch of principal: `PrincipalSwitched` carries the new principal and tenant in its context and the previous
  principal's recorded type and identifier as snapshots of its own, after the switch commits on the device's
  connection; it is scheduled before the guard binds the switched session.
- Refresh: the guard dispatches `Refreshed` and `SignedIn` with the session's context, including the tenant the
  exchange's activity check loaded and the method the device records, after the rotation commits on the device's
  connection, scheduling them before it binds the exchanged session.
- A write is reported before the guard binds to it, so a bind listener that throws (on `Validated`, `Login`,
  `Authenticated`, `PrincipalAssigned` or `DeviceAuthenticated`) cannot withhold the report: its exception still reaches
  the caller, and the events still never fire for a rolled-back write. With no transaction open they are dispatched
  before the bind events, so a listener on them reads the context, not the guard; inside a transaction they follow its
  commit. A listener that throws on a lifecycle event propagates as any listener does and stops what follows it, so
  independence from bind listeners is the guarantee, not delivery to every subscriber.
- Revocation: each `DeviceRevoked` carries the revoked device, the device's own guard and the method its session
  records, with the identity, principal and tenant the revocation knew, and the snapshots of the owner and principal
  the row records for those it did not; a bulk revocation then dispatches one `SignedOutEverywhere` per scope with the
  acting guard, the scope's identity (for a principal's scope, its owner read afresh, or none when that cannot be
  read), the principal scope or none, the kept device, the reason, the count and the cutoff it set (none when a
  device-less session kept the identity's cutoff), all after the device transaction commits (see
  `device-lifecycle.md`).
- Verification: `IdentifierVerified` carries the identity, the guard it was made for, and the client the caller passed,
  or the client of the request being served.
- Credentials: `PasskeyAdded`, `PasskeyUsed` and `PasskeyRemoved` carry the owner, the method `passkey` and the
  passkey's id, after the passkey row's connection commits (see `passkeys.md`); `ApiKeyIssued`, `ApiKeyRotated` (with
  the replaced key's id) and `ApiKeyRevoked` carry the key's owner, principal, tenant, id and scopes, after the key's
  connection commits; `ClientCredentialsGranted`, which reports no write, is dispatched at once with the key's id and
  the scopes granted (see `machine-credentials.md`).

## Failure / Edge Cases

- A refresh failure carries the device once the token's `did` loaded one, the identity once the owner reloaded, the
  principal once resolved, and the tenant only when it was admitted; before the device loads, the context keeps the
  token's `did` as the device snapshot (`deviceId`). A failure on the row's own state, before the owner was read, holds
  no identity or principal model, and its snapshots name the owner and principal the row records. A replay's
  `DeviceRevoked` likewise carries the device and its own guard and method, no identity or principal model (the replay
  is caught before the owner is loaded), and the snapshots of what the row records.
- A switch failure follows the same rule up to its target: once the owner is read, a refusal of the target (not the
  principal named, inactive, ineligible, a factor required) names the principal resolved for it, if any, never the
  one the device acts as.
- A refresh refused by the limits (`rate_limited`) carries the wait in `retryAfter`, and the guard then throws its 429.
- A queued listener of an event whose device was pruned before it ran cannot restore the event; the snapshots are the
  record to keep.

## Implementation Anchors

- `src/Events/EventContext.php`, `src/Contracts/AuthenticationEvent.php`, `src/Events/AuthenticationFailed.php`,
  `src/Events/Enums/FailureReason.php`, `src/Events/Enums/AuthenticationFlow.php`,
  `src/Events/Enums/RevocationReason.php`.
- `src/Guards/Concerns/BindsContextualState.php`: `bindContext()`, `boundContext()`, `boundTenant()`, and the context
  `setPrincipal()` and `setDevice()` report.
- `src/Guards/AbstractGuard.php`: `bindVerifiedContext()`, `authenticateAs()`, and the `attempt()` failure.
- `src/Guards/JwtGuard.php`: `refresh()`, `refuseRefresh()` and `reportRefresh()`; `src/Guards/BearerAuthentication.php`:
  `failed()`, the bearer failure's context.
- `src/Jwt/RefreshTokenExchange.php`: `refused()`, `deviceContext()`, and the `DeviceRevoked` dispatch;
  `src/Sessions/PrincipalSwitch.php`: `context()`.
- `src/Sessions/SessionService.php`: `signedIn()`, `fail()`; `src/Sessions/SessionPreconditions.php`: `methodReason()`;
  `src/Sessions/SignInResult.php`: `failed()`, the concealment.
- `src/Sessions/Concerns/ManagesDevices.php`: `endSessions()`, the `DeviceRevoked` and `SignedOutEverywhere` contexts.
- `src/Database/AfterCommit.php`: the commit-bound dispatch.

## Authoritative Tests

- `tests/Unit/Events/EventContextTest.php`
  `testSnapshotsEveryIdentifierAsAString`, `testSnapshotsDoNotFollowLaterChanges`,
  `testKeepsANamedDeviceIdWithoutADevice`, `testKeepsTheCredentialAndItsScopes`
- `tests/Feature/Events/EventContextTest.php`
  `testALoadedDeviceRowStandsInForAnUnloadedIdentityAndPrincipal`, `testWithoutFromDeviceTheRowStandsInForNothing`
- `tests/Unit/Events/Enums/FailureReasonTest.php`
  `testTheSignInMethodReasons`, `testTheConcealedReasons`
- `tests/Unit/Sessions/SignInResultTest.php`
  `testAConcealedReasonIsAnsweredAsInvalidCredentials`, `testAnUnconcealedMethodReasonIsKept`
- `tests/Unit/Contracts/ContractDeclarationTest.php`
  `testEveryPackageEventImplementsAuthenticationEvent`
- `tests/Feature/Guards/AbstractGuardEventContextTest.php`
  `testAListenerOnAuthenticatedSeesTheWholeContext`, `testTheBindEventsCarryTheWholeContext`,
  `testATenantThatCannotBeLoadedIsReportedAsNone`, `testAMisconfiguredTenantPropagatesFromATrustedBind`
- `tests/Integration/Events/SignInEventSerialisationTest.php`
  `testAQueuedEventHoldsIdentifiersAndNoSecret`, `testTheSnapshotsSurviveTheQueue`,
  `testAnEventWhoseDeviceWasDeletedCannotBeRestored`
- `tests/Integration/Events/CustomEventsIntegrationTest.php`
  `testOneListenerOnTheContractReceivesEveryPackageEvent`
- `tests/Integration/Guards/SeparateDeviceConnectionIntegrationTest.php`
  `testRefreshIsReportedAtOnceWhateverAnotherConnectionsTransactionDoes`,
  `testRefreshInsideTheDeviceConnectionsTransactionIsReportedOnItsCommit`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testAFailureIsReturnedNotDispatched`
- `tests/Feature/Sessions/SessionServiceTest.php`
  `testAMethodThatRefusesWithAServiceReasonIsAMisconfiguration`, `testASignInWhoseBindListenerThrowsIsStillReported`,
  `testACompletionWhoseBindListenerThrowsIsStillReportedAndGivesItsSlotsBack`,
  `testALifecycleListenerThatThrowsStopsTheBind`
- `tests/Feature/Sessions/ChoosesPrincipalsTest.php`
  `testAChoiceWhoseBindListenerThrowsIsStillReported`, `testASwitchWhoseBindListenerThrowsIsStillReported`
- `tests/Feature/Guards/JwtGuardTest.php`
  `testARefreshWhoseBindListenerThrowsIsStillReported`
- `tests/Integration/Sessions/SessionServiceTest.php`
  `testAThrowingBindListenerStillLetsTheSessionBeReported`,
  `testAThrowingBindListenerInsideTheCallersTransactionFollowsItsOutcome`,
  `testAThrowingBindListenerOnARefreshFollowsTheCallersTransaction`

## Change Triggers

Update this note when any of the following change:

- the parts of `EventContext` or what it snapshots
- an event that stops implementing `AuthenticationEvent`, or a new package event
- the commit-bound dispatch of an event that reports a write, or its place before the bind
- the failure event, its flows or its reasons
- which side dispatches the refresh exchange's failure
