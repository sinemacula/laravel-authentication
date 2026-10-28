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
  session records). A part that was not established is `null`.
- A context snapshots, when it is built, the identity's auth identifier, the principal's recorded type (its morph class,
  or its class name) and identifier, the tenant's identifier and the device's identifier, all as strings. A device id a
  token named is kept as the device snapshot when no device row was loaded.
- The snapshots, the enums, the client and the other strings are facts fixed at event time and survive a queue
  unchanged. The models are live references: a synchronous listener gets the instances the package holds, and a
  queued listener gets them re-fetched in their state when it runs, or Laravel's `ModelNotFoundException` when one was
  deleted meanwhile (a pruned device, say). Audit sinks should record the snapshots.
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
- One failure event, `AuthenticationFailed`, reports every failed sign-in, refresh and principal switch, with the flow
  (`AuthenticationFlow`) and a reason (`FailureReason`), the identifier a sign-in named, and the wait of a rate-limited
  failure. Where Laravel's `Failed` fires as well, it fires first and `AuthenticationFailed` second.
- A sign-in method may refuse only with `invalid_credentials` (`FailureReason::isSignInMethodReason()`); any other
  reason is the session service's to give, and a method that returns one is a misconfiguration (`LogicException`).
- `RefreshTokenExchange::exchange()` returns its `AuthenticationFailed` undispatched and its caller (the guard)
  dispatches it; the exchange itself dispatches only `DeviceRevoked`, after commit.

## Success Path

- Sign-in: the session service builds one context for a written session (guard, client, identity, principal, the
  tenant admission loaded, device, method) and dispatches `DeviceCreated` (new devices) and `SignedIn` with it after
  the device's connection commits. A sign-in held for a factor dispatches `AdditionalFactorRequired` with the proven
  device, after the pending sign-in commits, and one held for a choice of principal `PrincipalChoiceRequired`, with
  the identity, the method and the proven device but no principal or tenant.
- Switch of principal: the guard binds the switched session, then `PrincipalSwitched` carries the new principal and
  tenant in its context and the previous principal's recorded type and identifier as snapshots of its own, after the
  switch commits on the device's connection.
- Refresh: the guard binds the exchanged session, then dispatches `Refreshed` with the session's context, including the
  tenant the exchange's activity check loaded and the method the device records, after the rotation commits on the
  device's connection.
- Verification: `IdentifierVerified` carries the identity, the guard it was made for, and the client the caller passed,
  or the client of the request being served.

## Failure / Edge Cases

- A refresh failure carries the device once the token's `did` loaded one, the identity once the owner reloaded, the
  principal once resolved, and the tenant only when it was admitted; before the device loads, the context keeps the
  token's `did` as the device snapshot (`deviceId`). A replay's `DeviceRevoked` carries the device and its own guard
  and method, but no identity: the replay is caught before the owner is loaded.
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
- `src/Guards/JwtGuard.php`: `refresh()` and `reportRefresh()`.
- `src/Jwt/RefreshTokenExchange.php`: `refused()`, `deviceContext()`, and the `DeviceRevoked` dispatch.
- `src/Sessions/SessionService.php`: `signedIn()`, `fail()`, `methodReason()`.
- `src/Database/AfterCommit.php`: the commit-bound dispatch.

## Authoritative Tests

- `tests/Unit/Events/EventContextTest.php`
  `testSnapshotsEveryIdentifierAsAString`, `testSnapshotsDoNotFollowLaterChanges`,
  `testKeepsANamedDeviceIdWithoutADevice`
- `tests/Unit/Events/Enums/FailureReasonTest.php`
  `testOnlyInvalidCredentialsIsASignInMethodReason`
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
  `testAMethodThatRefusesWithAServiceReasonIsAMisconfiguration`

## Change Triggers

Update this note when any of the following change:

- the parts of `EventContext` or what it snapshots
- an event that stops implementing `AuthenticationEvent`, or a new package event
- the commit-bound dispatch of an event that reports a write
- the failure event, its flows or its reasons
- which side dispatches the refresh exchange's failure
