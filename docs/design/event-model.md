# Event Model

## Purpose

This note records what a package event is: the context every one carries, what survives a queue, when an event that
reports a write is dispatched, and how failures are reported. Audit sinks, SIEM forwarders and lockout notices attach
to these events, so the shape and the timing are a contract.

## Invariants

- Every event the package dispatches implements `Contracts\AuthenticationEvent` and carries one `Events\EventContext`
  (`context()` returns it), so one listener on the contract receives them all. Laravel's own auth events (`Attempting`,
  `Validated`, `Login`, `Authenticated`, `Failed`, `Logout`) do not.
- A context holds the guard (`null` only for a session that records none, or a verification link refused before its
  guard could be trusted), the client of the request being served (IP address and user agent, cleaned by
  `ClientContext`), and, as far as the flow established them, the identity, the principal, the tenant it acts within,
  the session, and the sign-in method (for a session's events, the method it records). Where a credential is involved it
  also holds the credential's id (`credentialId`: an API key's or a passkey's id) and the scopes it grants (`scopes`:
  the granted list for an API key or a client credentials token, `[]` for a machine bound without one, `null` for a
  human identity's session). A part that was not established is `null`.
- A context snapshots, when it is built, when (`occurredAt`, a `CarbonImmutable` to the microsecond), and, as strings,
  the identity's morph class (an Eloquent model's morph class, else its class name; the class name too for a model an
  enforced morph map leaves out, so building a context never throws `ClassMorphViolationException` for a tenant that
  never needed an alias) and auth identifier (`identityMorphClass`, `identityId`), the principal's morph class, as a
  session row records it, and identifier (`principalMorphClass`, `principalId`), the tenant's morph class and identifier
  (`tenantMorphClass`, `tenantId`) and the session's identifier (`sessionId`). A session id a token named is kept as the
  session snapshot when no session row was loaded. The morph class says which model a reference names, never what kind
  of principal it is: a caller's category is the application's to record, from the principal it is given.
- An event about a session row itself is built with `fromSession`: every `SessionRevoked`, and a refresh or switch
  refused on the row's own state before its owner was read (a `RefreshJudgment` verdict, `identity_unknown`, a row that
  changed under the compare-and-swap). An identity or principal it does not hold then takes the snapshot of the owner
  (its morph class and identifier) and the principal the row records, read from its attributes without a query; sessions
  record no tenant. Every other event keeps the snapshots of what it holds, even when it carries a session: an
  identity's `SignedOutEverywhere` (its session is the one kept), a `SessionPending` waiting on a choice of principal
  and a switch refused for its target name no principal.
- Everything in a context but its four models is the snapshot: facts fixed at event time, the record audit sinks keep,
  which survives a queue unchanged; `toArray()` gives it as scalars (snake_case keys, `occurred_at` as an ISO 8601 UTC
  string to the microsecond, the client as `ip` and `user_agent`), a payload a sink can store or queue on its own. It is
  attribution, not the whole record: the event's class and its own fields (a failure's flow and reason, a switch's
  previous principal) say what happened.
- The models are a convenience. A synchronous listener gets the instances the package holds. Across a queue
  (`Events\Concerns\SerializesLiveModels`, used by `EventContext` and for `PrincipalSwitched::$previousPrincipal`) an
  Eloquent model crosses as Laravel's model identifier and is fetched again from the writer when the event is restored,
  in its state then and with the relations it had loaded, or comes back `null` once its row is gone (a soft-deleted row
  is still there, and is restored); a database error still surfaces. A part that is not an Eloquent model does not cross
  and is `null` after a queue, so no arbitrary object enters the payload. A restored model is current state, not
  evidence of what was authorised: audit sinks record the snapshot.
- No event field carries a token, a digest, a password, a pending credential or any other secret. The session's digests
  are hidden from its serialisation; like Laravel's own auth events, the live identity model holds its attributes.
- An event that reports a write is dispatched through `Database\AfterCommit` on the written row's connection: at once
  when that connection has no open transaction, on its commit otherwise, and never on rollback. No package event
  implements `ShouldDispatchAfterCommit`, which would defer it to the last transaction of any connection. Events that
  report an in-memory bind (`PrincipalAssigned`, `SessionAuthenticated`) fire at once.
- A bind sets the identity, principal and session first and then dispatches `Authenticated`, `PrincipalAssigned` and
  `SessionAuthenticated?`, all describing the same context, so a listener on any of them reads the whole of it from the
  guard. A bind the guard verified (bearer, refresh, `attempt()`, the session service) reports the tenant its activity
  check loaded; a trusted bind (`login()`, `authenticateAs()`, `setUser()`, `setPrincipal()`, `setSession()`) reads the
  principal's tenant on the write connection and reports none when the tenant cannot be loaded
  (`TenantUnavailableException`), while a principal loaded without its tenant's key is a misconfiguration whose
  `LogicException` propagates.
- One failure event, `AuthenticationFailed`, reports every failed sign-in, refresh, switch, bearer token, API
  key, client credentials exchange, request for a one-time code and verification by code or link, with the flow
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
  dispatches it; the exchange itself dispatches only `SessionRevoked`, after commit.

## Success Path

- Sign-in: the session service builds one context for a written session (guard, client, identity, principal, the tenant
  admission loaded, session, method) and dispatches `SessionCreated` and `SignedIn` with it after the session's
  connection commits, scheduling them before it binds the guard; every sign-in creates its session. A sign-in that
  replaces the session the client proved first dispatches that session's `SessionRevoked` (`superseded`), with the
  sign-in's guard, client, identity, principal and tenant and the method the session records, in the same callback. A
  sign-in whose session is written pending dispatches `SessionPending` after it commits, with the pending session, the
  proven session, what it requires and its expiry, and the principal and tenant only once selected; its first
  activation dispatches `SessionCreated` and `SignedIn` as a sign-in does. A session that returns to pending from
  active dispatches `SessionReturnedToPending` (the flow, what it requires, its expiry, and the principal and tenant it
  left when they changed), and its later activation `SessionActivated`.
- Switch of principal or tenant: `PrincipalSwitched` carries the new principal and tenant in its context, the previous
  principal's recorded morph class and identifier and the previous tenant's identifier as snapshots of its own, and
  which of the two changed (`principalChanged`, `tenantChanged`), after the switch commits on the session's
  connection; it is scheduled before the guard binds the switched session, and only when something changed. A switch
  whose destination asks for a further factor dispatches `SessionReturnedToPending` (flow `switch`) instead.
- Refresh: the guard dispatches `Refreshed` and `SignedIn` with the session's context, including the tenant the
  exchange's activity check loaded and the method the session records, after the rotation commits on the session's
  connection, scheduling them before it binds the exchanged session.
- A write is reported before the guard binds to it, so a bind listener that throws (on `Validated`, `Login`,
  `Authenticated`, `PrincipalAssigned` or `SessionAuthenticated`) cannot withhold the report: its exception still
  reaches the caller, and the events still never fire for a rolled-back write. With no transaction open they are
  dispatched before the bind events, so a listener on them reads the context, not the guard; inside a transaction they
  follow its commit. A listener that throws on a lifecycle event propagates as any listener does and stops what follows
  it, so independence from bind listeners is the guarantee, not delivery to every subscriber.
- Revocation: each `SessionRevoked` carries the revoked session, the session's own guard and the method it records, with
  the identity, principal and tenant the revocation knew, and the snapshots of the owner and principal the row records
  for those it did not; a bulk revocation then dispatches one `SignedOutEverywhere` per scope with the acting guard, the
  scope's identity (for a principal's scope, its owner read afresh, or none when that cannot be read), the principal
  scope or none, the kept session, the reason, the count and the cutoff it set (none when an access-only token kept the
  identity's cutoff), all after the session transaction commits (see `session-lifecycle.md`).
- Verification: `IdentifierVerified` carries the identity, the guard it was made for, and the client the caller passed,
  or the client of the request being served. A refused verification link's `AuthenticationFailed` carries the guard only
  once the link's signature is correct and it names a configured JWT guard, and the identity only once it was loaded to
  check the link's digest: an unsigned claim is never taken as context, and no identity is read only to report a
  refusal.
- Credentials: `PasskeyAdded`, `PasskeyUsed` and `PasskeyRemoved` carry the owner, the method `passkey` and the
  passkey's id, after the passkey row's connection commits (see `passkeys.md`); `ApiKeyIssued`, `ApiKeyRotated` (with
  the replaced key's id) and `ApiKeyRevoked` carry the key's owner, principal, tenant, id and scopes, after the key's
  connection commits; `ClientCredentialsGranted`, which reports no write, is dispatched at once with the key's id and
  the scopes granted (see `machine-credentials.md`).

## Failure / Edge Cases

- A refresh failure carries the session once the token's `sid` loaded one, the identity once the owner reloaded, the
  principal once resolved, and the tenant only when it was admitted; before the session loads, the context keeps the
  token's `sid` as the session snapshot (`sessionId`). A failure on the row's own state, before the owner was read,
  holds no identity or principal model, and its snapshots name the owner and principal the row records. A replay's
  `SessionRevoked` likewise carries the session and its own guard and method, no identity or principal model (the replay
  is caught before the owner is loaded), and the snapshots of what the row records.
- A switch failure follows the same rule up to its target: once the owner is read, a refusal of the target (not the
  principal named, inactive, ineligible, a factor required) names the principal resolved for it, if any, never the
  one the session acts as.
- A refresh refused by the limits (`rate_limited`) carries the wait in `retryAfter`, which the refresh's result carries
  too.
- A queued listener of an event whose session, identity, principal or tenant was deleted before it ran (a pruned
  session, an erased account) still gets the event, with that model `null` and the snapshot naming it as it was.

## Implementation Anchors

- `src/Events/EventContext.php` (`toArray()`), `src/Events/Concerns/SerializesLiveModels.php`,
  `src/Contracts/AuthenticationEvent.php`,
  `src/Events/AuthenticationFailed.php`,
  `src/Events/Enums/FailureReason.php`, `src/Events/Enums/AuthenticationFlow.php`,
  `src/Events/Enums/RevocationReason.php`.
- `src/Guards/Concerns/BindsContextualState.php`: `bindContext()`, `boundContext()`, `boundTenant()`, and the context
  `setPrincipal()` and `setSession()` report.
- `src/Guards/AbstractGuard.php`: `bindVerifiedContext()`, `authenticateAs()`, and the `attempt()` failure.
- `src/Sessions/SessionRefresh.php`: `refresh()`, `refuse()` and `report()`; `src/Guards/BearerAuthentication.php`:
  `failed()`, the bearer failure's context.
- `src/Jwt/RefreshTokenExchange.php`: `refused()`, `sessionContext()`, and the `SessionRevoked` dispatch;
  `src/Sessions/SessionSwitch.php`: `eventContext()`.
- `src/Sessions/SessionEstablishment.php`: `signedIn()`; `src/Sessions/SessionService.php`: `fail()`;
  `src/Sessions/SessionPreconditions.php`: `methodReason()`; `src/Sessions/SignInResult.php`: `failed()`, the
  concealment.
- `src/Sessions/SessionRevocations.php`: `endSessions()`, the `SessionRevoked` and `SignedOutEverywhere` contexts.
- `src/Database/AfterCommit.php`: the commit-bound dispatch.

## Authoritative Tests

- `tests/Unit/Events/EventContextTest.php`
  `testRecordsWhenItWasBuilt`, `testSnapshotsEveryReferenceAsAString`, `testRecordsEloquentModelsByTheirMorphClass`,
  `testSnapshotsDoNotFollowLaterChanges`, `testKeepsANamedSessionIdWithoutASession`,
  `testKeepsTheCredentialAndItsScopes`, `testToArrayIsTheSnapshotAsScalars`, `testSurvivesASerializeRoundTrip`,
  `testAModelAnEnforcedMorphMapLeavesOutIsRecordedByItsClassName`
- `tests/Feature/Events/Concerns/SerializesLiveModelsTest.php`
  `testALiveModelIsFetchedAgainInItsStateThen`, `testALiveModelWhoseRowIsGoneComesBackNull`,
  `testAPartThatIsNotAnEloquentModelDoesNotCross`, `testADatabaseErrorStillSurfaces`,
  `testAPreviousPrincipalWhoseRowIsGoneComesBackNull`, `testALiveModelNamedByItsMorphAliasIsRestored`
- `tests/Integration/Events/ReplicaSerializesLiveModelsTest.php`
  `testALiveModelIsFetchedAgainFromTheWriter`
- `tests/Integration/Events/EveryEventRestoresTest.php`
  `testTheEventRestoresWithItsSnapshotOnceItsRowsAreGone`, `testEveryPackageEventIsChecked`
- `tests/Feature/Events/EventContextTest.php`
  `testALoadedSessionRowStandsInForAnUnloadedIdentityAndPrincipal`, `testWithoutFromSessionTheRowStandsInForNothing`
- `tests/Unit/Events/Enums/FailureReasonTest.php`
  `testTheSignInMethodReasons`, `testTheConcealedReasons`
- `tests/Unit/Sessions/SignInResultTest.php`
  `testAConcealedReasonIsAnsweredAsInvalidCredentials`, `testAnUnconcealedMethodReasonIsKept`
- `tests/Unit/Contracts/ContractDeclarationTest.php`
  `testEveryPackageEventImplementsAuthenticationEvent`
- `tests/Feature/Guards/AbstractGuardEventContextTest.php`
  `testAListenerOnAuthenticatedSeesTheWholeContext`, `testTheBindEventsCarryTheWholeContext`,
  `testATenantThatCannotBeLoadedIsReportedAsNone`, `testAMisconfiguredTenantPropagatesFromATrustedBind`
- `tests/Integration/Events/SignInEventSerializationTest.php`
  `testAQueuedEventHoldsIdentifiersAndNoSecret`, `testTheSnapshotsSurviveTheQueue`,
  `testAnEventWhoseRowsWereDeletedStillRestores`, `testAQueuedListenerOnTheSyncConnectionGetsTheSnapshotOfDeletedRows`,
  `testAQueuedListenerRunByAWorkerGetsTheSnapshotOfDeletedRows`
- `tests/Integration/Events/CustomEventsIntegrationTest.php`
  `testOneListenerOnTheContractReceivesEveryPackageEvent`
- `tests/Integration/Guards/SeparateSessionConnectionIntegrationTest.php`
  `testRefreshIsReportedAtOnceWhateverAnotherConnectionsTransactionDoes`,
  `testRefreshInsideTheSessionConnectionsTransactionIsReportedOnItsCommit`
- `tests/Feature/Jwt/RefreshTokenExchangeTest.php`
  `testAFailureIsReturnedNotDispatched`
- `tests/Feature/Sessions/SessionServiceTest.php`
  `testAMethodThatRefusesWithAServiceReasonIsAMisconfiguration`, `testASignInWhoseBindListenerThrowsIsStillReported`,
  `testACompletionWhoseBindListenerThrowsIsStillReportedAndGivesItsSlotsBack`,
  `testACompletionWhoseBindListenerThrowsFollowsTheCallersTransaction`, `testALifecycleListenerThatThrowsStopsTheBind`
- `tests/Feature/Sessions/ChoosesPrincipalsTest.php`
  `testAChoiceWhoseBindListenerThrowsIsStillReported`, `testAChoiceWhoseBindListenerThrowsFollowsTheCallersTransaction`,
  `testASwitchWhoseBindListenerThrowsIsStillReported`, `testASwitchWhoseBindListenerThrowsIsReportedOnTheCallersCommit`,
  `testAChoiceUnderAnEnforcedMorphMapRecordsAnUnmappedTenantByItsClass`
- `tests/Feature/Guards/JwtGuardTest.php`
  `testARefreshWhoseBindListenerThrowsIsStillReported`
- `tests/Integration/Sessions/SessionServiceTest.php`
  `testAThrowingBindListenerStillLetsTheSessionBeReported`,
  `testAThrowingBindListenerInsideTheCallersTransactionFollowsItsOutcome`,
  `testAThrowingBindListenerOnARefreshFollowsTheCallersTransaction`

## Change Triggers

Update this note when any of the following change:

- the parts of `EventContext`, what it snapshots, or how its models cross a queue
- an event that stops implementing `AuthenticationEvent`, or a new package event
- the commit-bound dispatch of an event that reports a write, or its place before the bind
- the failure event, its flows or its reasons
- which side dispatches the refresh exchange's failure
