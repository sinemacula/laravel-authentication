# Sessions: proofs, stepping up, freshness, switching principal, signing out and the caller of a request

## Proofs and provenance

Every session records the proofs it was established and kept with, each a timestamped row in `proofs.table` (see
[Proofs](configuration.md#proofs)), kept apart by kind:

| Kind                            | Recorded by                                                                                                                                                                                |
|---------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `first_factor`                  | every sign-in: what the sign-in method verified (see [Writing a sign-in method](signing-in.md#writing-a-sign-in-method)), or the external provider's result `signInExternally()` was given |
| `first_factor_reauthentication` | a reauthentication with the first factor on an active session                                                                                                                              |
| `additional_factor`             | a further factor an adapter verified: at sign-in, with `satisfy()`, or as a step-up                                                                                                        |
| `recovery_code`                 | a recovery code an adapter accepted in place of a further factor                                                                                                                           |
| `external_reauthentication`     | a reauthentication at the external provider the session began with, through the link that established it (`reauthenticateExternally()`)                                                    |

Each holds its method, its channel (`password`, `sms`, `email`, `authenticator_app`, `passkey`, `external_provider` or
`unknown`, with the destination or credential reference: a code's address or number in its normal form, a passkey's own
row id, a provider's connection id), the factor an adapter used, what was observed about the authenticator (user
presence and verification, backup eligibility and state, phishing resistance, key protection: each `null` when it was
not observed, which never counts as true), the adapter's evaluation (accepted, multifactor; none for a proof the package
verified itself, except an external one whose evidence was accepted), the external provider's evidence once accepted,
its `amr` values, its time and its binding (the identity, the application, the session and the purpose: `sign_in`,
`reauthenticate` or `step_up`). A proof is never changed once recorded, except to be marked void, after which it never
counts: when the factor package removes a factor, `factorRemoved()` voids the proofs the current session made with it,
and the identity's other sessions end (see [Sign-in factors](#sign-in-factors)). A removed first-factor credential
(`credentialRemoved()`) voids nothing.

A session an external provider established (`signInExternally()`, see [External
sign-in](signing-in.md#external-sign-in)) also records its provenance, once, in `proofs.provenance_table`: the
connection and its tenant, the provider's authentication time, the evidence the provider asserted once accepted, the
provider's deadline for its session (which also caps the session's absolute deadline, the earlier of it and the
sign-in's own winning), the policy version the adapter checked, and the id of the link the result was mapped to its
identity through, kept byte for byte. A later reauthentication at the provider is a proof of its own and never rewrites
how the session began. The provenance is indexed by connection and by tenant: the sessions a connection established are
revoked through it (see [Connections and links](#connections-and-links)); there is no lookup by connection or tenant
yet.

A provider's evidence (its `amr` values, its `acr` value or SAML authentication context class reference, and the time it
is for) counts for nothing until the application binds an `ExternalEvidencePolicy` that accepts it (see [Tenant
authentication policies](extending.md#tenant-authentication-policies)). Evidence the policy accepts for multifactor
authentication, an additional verification, phishing resistance or any assurance level is accepted: it is recorded with
the proof that brought it, and with the provenance at sign-in; the proof's evaluation is accepted, and multifactor when
it was accepted for multifactor authentication, so `amr` gains `mfa` (in every token of the session: the claims say how
it authenticated, not what a tenant accepts); and the identity-level requirement and a tenant's are met when the policy
says any accepted evidence, the newest first, meets the whole of one, so newer evidence accepted for less never hides
older evidence that still meets it (among the 50 newest proofs that carry evidence; older ones are not read). A proof
that carries evidence reads back with no evaluation, so a requirement check never counts the acceptance itself. Evidence
that is not accepted is never recorded, and a reauthentication at the provider without accepted evidence renews
`auth_time` and nothing else. Freshness takes no provider's evidence: a provider's proof meets a freshness requirement
on its own time, but never one that asks for multifactor authentication, whatever its evidence says. A result's evidence
may not be dated after the provider's time the result gives (an `InvalidArgumentException`): that time times the proof,
and the evidence's own time is what its acceptance and a requirement judged on it age.

Proofs and provenance belong to the session's key, so they carry unchanged from a pending session to the active one it
becomes, and across every refresh and switch. A sign-in that replaces a session the client proved it holds is a new
session with its own proofs; the replaced session keeps its own. A new session counts only its own sign-in's: anything
recorded under its key before (by an earlier session whose key the database issued again) is deleted as it records them.
`auth_time` and `amr` are derived from the proofs when an access token is issued, never stored in their place. Every
read of them is from the write connection, so a lagging replica cannot hide a proof just written. They hold personal
data (a code's destination), are hidden from a model's serialised form, and are pruned with their session (see
[Pruning](operations.md#pruning)).

## Stepping up

A session steps up when your further-factor adapter verifies a factor on it: a one-time password, a passkey used as a
factor, or a recovery code in its place. Hand the adapter's `Proofs\ProofResult` to the session service; it records the
proof on the session and issues the session a new access token, and nothing else:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;

Route::middleware('auth:api')->post('/step-up', function (Request $request) {
    $proof  = $factors->verify(Auth::identity(), Auth::session(), $request->input('code')); // your adapter's ProofResult
    $result = Auth::sessions('api')->stepUp($proof);

    return $result->isIssued()
        ? SecretResponse::json(['access_token' => $result->accessToken, 'expires_at' => $result->expiresAt->toIso8601String()])
        : response()->json(['message' => 'The code was not accepted.'], 403);
});
```

The proof must be an `additional_factor` or a `recovery_code`, made for `Purpose::STEP_UP`, accepted by its adapter's
`Evaluation`, and made no later than now and no earlier than the session started (`proof_invalid` otherwise); its
`ProofBinding` must name the session's owner, this guard and the session's key (`proof_binding_mismatch`). The session
is read again and locked while the proof is recorded, so it must still be one of the guard's live, active sessions of a
person (`session_unknown`, `session_guard_mismatch`, `session_revoked`, `session_pending`, `session_expired`,
`machine_identity`), and it is admitted again as a refresh admits it (its owner, principal and tenant active, the method
still allowed, the principal still eligible). A revocation that commits first refuses the step-up; one that commits
after ends the new token at its next request, as it ends every access token of the session.

The new access token's `auth_time` is the newest time of the session's proofs, so never earlier than the step-up proof's
(a reauthentication recorded after the proof was made keeps its own, later time), and its `amr` gains the proof's
values, and `mfa` when the evaluation reports multifactor authentication. The session keeps its key, its refresh token
and its deadlines: a refresh afterwards issues tokens that still carry the step-up, since `auth_time` and `amr` are
derived from the session's proofs each time a token is issued. No refresh token is issued and nothing is bound to the
request, which is already authenticated. `SteppedUp` reports it once committed, with the proof's kind and, as the
context's method, the method the adapter verified it with; a refusal is an `AccessTokenResult` whose `reason` says why,
reported by `AuthenticationFailed` with the flow `step_up` and the same method, and never thrown.

## Reauthenticating

A session reauthenticates when its identity proves its first factor again, through one of the guard's sign-in methods
and the input the client sent:

```php
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;

Route::middleware('auth:api')->post('/reauthenticate', function (Request $request) {
    $result = Auth::sessions('api')->reauthenticate(Auth::session(), 'password', $request->only('email', 'password'));

    return match (true) {
        $result->isIssued()                                => SecretResponse::json(['access_token' => $result->accessToken]),
        $result->reason === FailureReason::RATE_LIMITED    => response()->json([], 429, ['Retry-After' => $result->retryAfter]),
        default                                            => response()->json(['message' => 'Those details are not correct.'], 403),
    };
});
```

Any sign-in method the guard allows can reauthenticate, with the input its sign-in takes. A code method (`phone_code`,
`email_code`) takes the identifier and a code sent for it: request one first with `Auth::codes('api')->send()`, as for a
sign-in and counted under the same code request limits (see [Signing in with a one-time
code](signing-in.md#signing-in-with-a-one-time-code)), then pass the identifier, the challenge id the request answered
(`CodeRequest::$challengeId`) and the code (`['phone' => $phone, 'challenge' => $challengeId, 'code' => $code]`); input
without a well-formed challenge id is refused as `invalid_credentials`, and the code is used up as a sign-in's is. A
passkey takes the `challenge` and `credential` of a ceremony begun with `Auth::passkeys('api')->signInOptions()` (see
[Using passkeys](signing-in.md#using-passkeys)). Whichever the method, the identity it verifies must be the session's
owner.

The method must be one the guard's application allows (`method_not_allowed`, nothing counted), and neither a machine
credential's nor `external_provider` (an `InvalidArgumentException`; see [At the external
provider](#at-the-external-provider)). The session must still be the one given, as stored (a session put under its key
since, of the same owner or not, records another generation and is `session_unknown`), and one of the guard's live
sessions of a person, as for a step-up. The attempt counts against the guard's `sign_in` limits, on the identifier and
the IP address, before any transaction opens (`rate_limited`, with the wait), and the method verifies the input in the
guard's credential timebox, its account checks counted as a sign-in's are. The identity it verifies must be the
session's owner: another identity's correct credential is `invalid_credentials`, as a wrong one is, and never says whose
it was. A concealed reason (`account_rate_limited`, an expired or exhausted code, a passkey's sign counter that did not
advance) is answered as `invalid_credentials`, with no wait. The session is then locked, checked again (still the
owner's, and of the generation verified) and admitted again, as for a step-up, the proof is recorded as
`first_factor_reauthentication`, and the slots are given back.

A reauthentication renews the session's authentication time and nothing else: the new access token's `auth_time` is now,
its `amr` is the session's as it was, and a further factor the session holds keeps its own time, so an operation that
asks for a further factor within a minute is not met by a fresh password. `Reauthenticated` reports it once committed; a
refusal is reported by `AuthenticationFailed` with the flow `reauthentication`.

### At the external provider

A session an external identity provider established reauthenticates at that provider through
`reauthenticateExternally($sessionId, $result)`, which a trusted server-side adapter calls with the identifier of the
session its handoff names (never the session the request happens to be authenticated with) and the result the provider
verified (from a reauthentication handoff it redeemed, say), never a client:

```php
$result = Auth::sessions('api')->reauthenticateExternally($redeemed->sessionId, new ExternalResult(
    connectionId: $redeemed->connectionId,
    issuer: $redeemed->issuer,
    subject: $redeemed->subject,
    authenticatedAt: $redeemed->authenticatedAt,
    evidence: $redeemed->evidence,
));
```

Only on an application that allows `external_provider` (`method_not_allowed`), only for one of the guard's live, active
sessions of a person, as for a step-up (an identifier that names no session, or cannot be a key, is `session_unknown`),
and only with the time the provider authenticated the identity (`proof_invalid` without one, or with one before the
session began). The result must come through the very link that established the session: the link contract must link it
to an identity (`ExternalResultUnlinked`, then `external_result_unlinked`), that identity must own the session, and the
session's provenance must record exactly the result's connection and the link's id, compared byte for byte
(`link_mismatch`, as for another link of the same identity through the same connection, a session no link established,
or a result naming another link than the contract answers). The link contract is asked before anything is locked; the
session's row is then locked, after every lock the adapter took, and judged again (still the session read before the
lock, its provenance and the provider's time), so call it inside the adapter's transaction on the storage connection.
With the proof recorded, the session must still meet its tenant's authentication policy, as at any redemption: a
connection the tenant no longer admits is `sso_required`, and a further factor it now requires that none of the
session's accepted evidence, this proof's included, meets is `additional_factor_required`; either rolls the proof back
and writes nothing, so the next refresh revokes the session or returns it to pending. The tenant's policy and the
evidence policy are asked then, under the session's row lock, so they must only read, or take no lock the adapter does
not already hold. A database error, a serialization failure included, propagates for the adapter to retry the whole
transaction.

The proof is recorded as `external_reauthentication`, timed when the provider authenticated the identity (now, when that
is after now), so the new access token's `auth_time` is the later of the session's and the provider's, decided under the
lock (inside a transaction of yours at REPEATABLE READ, from the proofs its snapshot holds, so a racing reauthentication
committed after your first read is left out of that one token, which is then older, never fresher). Nothing else is
renewed: no refresh token is issued, and the session row, its deadlines and its provenance are kept. Its `amr` gains the
provider's private value, and `mfa`, only when the application's `ExternalEvidencePolicy` accepts the result's evidence
(see [Proofs and provenance](#proofs-and-provenance)); otherwise only `auth_time` moves. `Reauthenticated` (method
`external_provider`) reports it once committed. A step-up refuses an external proof.

An adapter asks `externalStanding($sessionId, $identity, $connectionId, $linkId)` whether a session, by its identifier,
stands for such a reauthentication: `null` for one of the guard's live, active sessions of a person owned by the
identity and established through exactly that connection and link, on an application that allows `external_provider`,
and otherwise the reason (`method_not_allowed`, `session_unknown`, `session_guard_mismatch`, `session_revoked`,
`session_pending`, `session_expired`, `machine_identity`, `link_mismatch`). Without a link id, a session established
through the connection and any link stands (one recorded with no link never does), for an adapter asked when a
reauthentication flow starts, before the exact link is known. Asked outside a transaction, it reads the session on the
write connection and locks nothing; asked inside the adapter's transaction, before it renews, it locks the session's row
until the transaction ends. It writes and reports nothing.

## Freshness

Whether a session's authentication is fresh enough for a sensitive operation is the `Contracts\FreshnessPolicy`'s to
say, judged on the newest of the session's proofs that meets the operation's requirement, never on the latest
`auth_time`: a step-up with a one-time password a minute ago does not make a session fresh for an operation that asks
for a phishing-resistant proof, though its token's `auth_time` is a minute old.

```php
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;

$freshness = app(FreshnessPolicy::class);

// The configured requirement for the operation on the session's application.
$proof = $freshness->freshProof(Auth::session(), 'mfa.add_factor');

// Made stricter by the caller's own: the shorter age, the kinds both take, either's flags.
$proof = $freshness->freshProof(Auth::session(), 'payouts.change', new FreshnessRequirement(300, [ProofKind::ADDITIONAL_FACTOR], multifactor: true));

// A maximum age alone: every kind counts, so only the configured age is shortened.
$proof = $freshness->freshProof(Auth::session(), 'sso.reauthenticate', FreshnessRequirement::within(300));

if ($proof === null) {
    return response()->json(['message' => 'Confirm it is you.', 'step_up' => true], 403);
}
```

`freshProof()` answers the proof that makes the session fresh (a `Proofs\RecordedProof`, with its kind, method, channel,
evaluation and time), or `null`. The requirement is configured per operation in `freshness` and per guard (see
[Freshness](configuration.md#freshness)): the proof kinds that count, how recently one must have been made, and whether
it must have reported multifactor authentication or been observed to resist phishing. An operation with no configured
requirement and none of the caller's is never fresh, nor is one whose two requirements take no kind in common. A proof
marked void never counts (nothing marks one yet). The session is never trusted as the caller holds it: it is read again
on the write connection and must still record the same generation and owner (a retained instance of a session whose key
now holds another, a later one of the same identity included, is never fresh) and be live for its guard before its
proofs are read, two queries in all, and none when the operation has no requirement. That read takes no lock, and inside
a transaction it may be served from a snapshot taken before the caller's lock (MySQL's REPEATABLE READ), so a caller
that acts on the answer atomically locks the session in its transaction, checks the locked row is still live itself, and
asks inside it, as an identifier change does (see [Changing identifiers](identifier-changes.md)).

`freshUntil()` answers until when the session stays fresh for the operation: the second its fresh proof is as old as
the effective requirement's maximum age, from which second on it is no longer fresh, or `null` when it is not fresh.
Both take an excluded factor as their last argument (`freshProof($session, $operation, $requirement, $factor)`): a
proof made with that factor never counts, so a factor's removal is authorised only by the session's other proofs.

The package binds `Freshness\ConfiguredFreshness`. Rebind the contract for a requirement the stored proofs cannot show,
such as a minimum assurance level or an additional verification of your own; an implementation keeps no state between
calls.

## Changing further factors

The factor package asks the session service before it adds, replaces or removes one of an identity's further factors,
or generates its recovery codes, from the session the change is made on. It asks inside the transaction that makes the
change, on the storage connection, after its own locks:

```php
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChange;

$verdict = Auth::sessions()->factorChange(Auth::session(), FactorChange::REMOVE, factor: $factor->reference());

if (!$verdict->isAllowed()) {
    return response()->json(['message' => 'Confirm it is you.', 'reason' => $verdict->reason?->value], 403);
}
```

The session's row is locked until that transaction ends, so a revocation either commits first, and the change is
refused, or waits for it. The session must still be the one given, one of this guard's live, active sessions
(`session_unknown`, `session_guard_mismatch`, `session_revoked`, `session_pending`, `session_expired`) and a person's
(`machine_identity`). Then it must be fresh for the change:

| Change                                                | Operation                 | Default proofs (within 15 minutes)                     | Refused as                  |
|-------------------------------------------------------|---------------------------|--------------------------------------------------------|-----------------------------|
| `ADD`, `REPLACE`, `REMOVE`, `GENERATE_RECOVERY_CODES` | `factor_change`           | A further factor or a recovery code                    | `step_up_required`          |
| `ADD_FIRST` (the identity's first additional factor)  | `first_additional_factor` | A reauthentication (first factor or external provider) | `reauthentication_required` |

An identity with no further factor has nothing to step up with, so its first one takes a reauthentication instead, and
never the sign-in's own first factor: whoever holds a session must prove the first factor again before enrolling a
factor on it. Only the factor package knows whether the identity has a factor, so it names `ADD_FIRST`. A replacement or
a removal names the factor it acts on (and only those name one: an `InvalidArgumentException` otherwise), whose own
proofs never count. A requirement of the factor package's own is passed as the third argument, and the stricter
applies. An allowed `FactorChangeVerdict` carries the fresh `proof` and `freshUntil`, the second the session stops being
fresh for the change; a refused one carries the `reason`. The gate writes nothing and reports nothing: once a removal
is made, in that same transaction, the factor package ends the sessions it affects with `factorRemoved()` (see [Sign-in
factors](#sign-in-factors)).

A pending session never goes through the gate: its first factor is enrolled through its pending credential's
`PendingAction::START_BOOTSTRAP_ENROLLMENT` and `CONFIRM_BOOTSTRAP_ENROLLMENT` actions
(`mfa.start_bootstrap_enrollment`, `mfa.confirm_bootstrap_enrollment`) while the factor is its first outstanding
requirement (see [Pending sessions](signing-in.md#pending-sessions)).

## Switching principal or tenant

An identity that may act as several principals (memberships of several tenants, say) switches the principal it acts as
to another one, in the same session, proven by the session's refresh token; a principal the application lets act in
tenants other than its own (see
[Letting principals act in other tenants](extending.md#letting-principals-act-in-other-tenants)) switches the session's
active tenant the same way. A `SwitchTarget` says where the session goes:

```php
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;

$target = $request->has('membership')
    ? SwitchTarget::principal(Membership::findOrFail($request->input('membership')))  // in its own tenant
    : SwitchTarget::tenant(TenantSelection::of($request->input('tenant')));           // the same principal

$result = Auth::sessions('api')->switchFromRequest($target);

abort_if($result === null, 401); // no refresh token in the request

if ($result->isFailed()) {
    // AuthenticationFailed was dispatched (flow switch); $result->reason says why.
    if ($result->reason === FailureReason::RATE_LIMITED) {
        // A 429 with Retry-After, as a refused refresh answers, so clients wait.
        throw new ThrottleRequestsException(__('Too Many Attempts.'), null, ['Retry-After' => $result->retryAfter]);
    }

    abort(401);
}

if ($result->isPending()) {
    // The destination's tenant asks for a further factor the session lacks.
    return SecretResponse::json(['pending_credential' => $result->credential, 'actions' => $result->pending->actions()]);
}

$tokens = $result->session->tokens;

// A cookie application's pair carries the cookie that sets the new refresh token; a body application's, the token.
return $tokens->refreshCookie?->attachTo(SecretResponse::json(['access_token' => $tokens->accessToken]))
    ?? SecretResponse::json(['access_token' => $tokens->accessToken, 'refresh_token' => $tokens->refreshToken]);
```

`SwitchTarget::principal($principal)` switches to another principal of the identity in its default tenant (its own),
`SwitchTarget::principal($principal, TenantSelection::of($id))` in the tenant named, and
`SwitchTarget::tenant(TenantSelection::of($id))` keeps the principal the session acts as and moves it to the tenant
named (`TenantSelection::principalDefault()` back to its own, `TenantSelection::none()` to none, which only a principal
that belongs to no tenant may by default).

A switch screen lists the destinations with `principals()` and gets one of them by its id with `principal()`:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;

$sessions = Auth::sessions('api');
$type     = Auth::session()?->getSignInIdentifierType();

$destinations = $sessions->principals(Auth::identity(), $type);
$destination  = $sessions->principal(Auth::identity(), $request->input('membership'), $type) ?? abort(404);
```

`principal($identity, $principalId, $identifierType)` answers the principal `principals()` would list with that
principal identifier, or `null` when it is not the identity's, is not admitted (inactive, in an inactive tenant, refused
by `ApplicationAccess`, or the identity refused with the identifier type) or two of the identity's principals share the
identifier, without saying which. It reads the very candidates `principals()` reads (the identity's `principals()` on
the write connection, or the resolver's default for an identity that is its own principal), in one query, and admits
only the one the id names, so it is found exactly when the list holds it. The switch checks its destination again.

The refresh token proves the session, never an access token: a stolen access token lives minutes and must not mint a
refresh credential. `switchFromRequest()` reads it as the session service's `refreshFromRequest()` does (see
[Refreshing](refreshing.md)), through the application's refresh token transport, so it comes by the application's own
transport and a token from the refresh cookie gets the cookie's cross-site checks; put the switch route under the
cookie's path. It returns `null` when the request carries no token, and a token the transport refuses fails with its
reason (`refresh_token_conflict`, `refresh_transport_mismatch`, `cross_site_request`, `token_invalid`, reported as an
`AuthenticationFailed` of flow `switch`) without the session being touched. The result's `source` says where the token
came from, and a cookie application's switched pair carries the cookie that sets the new refresh token, never the
token, as a refresh does. `switchTo($refreshToken, $target)` remains for a body application's token your code reads
itself; on a cookie application it throws a `LogicException`.

A switch is judged as a refresh is: counted against the same refresh limits (`rate_limited`, with the wait in the
result's `retryAfter`: a switch returns its refusal, as a refresh does, so answer it with `Retry-After` as above), the
token parsed for this guard, the session found, of this guard, live, and the rotation id current, or the previous one
inside the grace window; any other id is a replay and revokes the session (`rotation_reuse`). On every path the
session's owner must still be returned by the guard's provider and be active; the destination principal (the target, or
the one the session records for a tenant-only switch) must resolve through the resolver's hinted path as the very
principal named, of its class, owned by that identity (read from the principal's own key, not trusted to the resolver),
active, in an active tenant of its own, allowed the application by `ApplicationAccess` (`principal_ineligible`) and
admitted by the application policy, also with the type of identifier the session's sign-in used (which the session
records), so a principal your policy refuses to that identifier cannot be reached by switching to it; the session's
sign-in method must still be allowed; and the destination tenant must be one `TenantAccess` lets the principal act in
(`tenant_ineligible`, also for a tenant `TenantResolver` cannot find) and active (`tenant_inactive`).

Then the destination tenant's authentication policy judges the session, with the proofs and provenance it already holds:
a policy that requires connections the session was not established through refuses the switch (`sso_required`) and
leaves the session as it was, and one that asks for a further factor the session lacks returns the session to pending
with the destination recorded, instead of re-issuing its pair. The result is then `isPending()`, carrying the pending
session (`pending`) and its credential (`credential`, only ever in the response's body); a guard the request already
bound to the session forgets it, with no event; the session's tokens are refused until the factor is given (see [Signing
in](signing-in.md)), and it then activates as the destination. The identity-level additional-factor policy is asked only
then, once the destination's policy has returned the session to pending, so the pending session names both what the
tenant asks and what the identity still owes; a switch the destination's policy lets through never asks it.

With the current rotation id, the token's principal must be the one the session records (`session_principal_mismatch`).
The switch keeps the session's absolute deadline, or its having none while the guard sets no limit, held to the guard's
absolute lifetime counted from the sign-in (`session_expired` when that has passed), restarts the idle one under the
guard's lifetimes, issues both tokens for the destination, then records the destination principal and tenant, the switch
time (`switched_at`), the tenant policy version, the rotation and both deadlines in one compare-and-swap. The session
keeps its key, so its proofs and provenance carry over unchanged. Every access token issued before a switch that changed
the principal or the tenant stops at once: one naming the other tenant is refused as `session_tenant_mismatch`, one
naming the other principal as `session_principal_mismatch`, and one issued before the switch as `session_switched`, so
switching back does not revive them (see [Session](configuration.md#session)). Two switches in one second record the
second one second later, so the tokens the second issues are refused until the client refreshes after that second. A
switch to the principal and tenant the session already records rotates the credential like a refresh and reports no
switch.

With the previous rotation id inside the grace window, the current credential for the destination is handed back,
writing nothing, only when the session records the destination principal and tenant and either its last rotation was the
switch to them (a lost switch response, retried) or the token's own principal is the destination; anything else is
`rotation_conflict`, without revoking, and the client retries with its current token. The retry is held to the
destination tenant's authentication policy as a refresh with the same token is: a tenant that now requires a connection
the session was not established through refuses it as `sso_required`, leaving the session as it was, and one that asks
for a further factor the session lacks returns the session to pending. When another request changes the session between
the switch's read and its write, the row is read again with a lock and judged once more under the same rules; the swap
is never tried twice.

A switch schedules `PrincipalSwitched` for its commit on the session's connection, with the new principal and tenant in
its context, the previous principal as the session recorded it (`previousPrincipalType`, `previousPrincipalId`)
and, when it still resolves for the identity, the principal itself (`previousPrincipal`), the previous tenant's
identifier (`previousTenantId`) and which of the two changed (`principalChanged`, `tenantChanged`), before it binds the
guard to the destination in the destination tenant (`Authenticated`, `PrincipalAssigned`, `SessionAuthenticated`, no
`Login`; `Auth::tenant()` is the new tenant) once the switch commits too, so a listener that throws on those cannot
withhold the report. Outside a transaction `PrincipalSwitched` is therefore dispatched before the bind events, and a
listener on it reads the event's context, not the guard, which still holds the previous principal; inside your
transaction both follow the commit, in that order, and a rollback drops both, leaving the guard unbound. The result
carries the new pair at once (a cookie application's refresh cookie in it, which the package never queues: attach it
only once your transaction has committed). A bind that waited for your commit binds only while the guard still serves
the request and the session, read again, still acts as the destination principal in the destination tenant.

## Signing out and revoking sessions

`Auth::logout()` (or `Auth::guard('api')->logout()`) signs the request's session out: the session the guard is bound to
is revoked with reason `signed_out`, `SessionRevoked` reports it once committed, Laravel's `Logout` follows, and the
guard stays signed out for the rest of the request. The session's access and refresh tokens stop at once. A request
without a persisted session (an access-only token) has nothing to revoke and is only forgotten; a guest request does
nothing. `Auth::sessions('api')->signOut()` does the same and returns whether it revoked a session.

Both need a live access token. A client whose access token has expired, or that holds none, signs out with its refresh
credential instead, and a logout route answers either way with `signOutFromRequest()`:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;

Route::post('/auth/logout', function () {
    $result = Auth::sessions('browser')->signOutFromRequest();

    // The expired cookie, when the result carries one, clears the browser's either way.
    return $result->attachTo($result->isFailed() ? response()->json(['reason' => $result->reason?->value], 401) : response()->noContent());
});
```

A request whose access token is bound to a stored session is signed out as `signOut()` signs it out, and its refresh
credential is not read. Otherwise any binding is forgotten first (an access-only token's, with `Logout`, the guard
staying signed out), and the refresh credential is read through the application's transport, as a refresh reads it:
the cookie of a cookie application, with its cross-site checks, or the body field or header of a body application. The
session it proves is revoked (`signed_out`, `SessionRevoked` once committed), `Logout` fires for its owner when the
guard's provider still returns it and none fired already, and a binding to it is forgotten. The token is judged as a
refresh judges it, short of rotating it: one the transport refuses fails with its reason (`refresh_token_conflict`,
`refresh_transport_mismatch`, `cross_site_request`, `token_invalid`), and so does one whose session is unknown, of
another guard, revoked, pending, expired or no longer recording the principal the token names; a replayed token revokes
its session as `rotation_reuse`, as a refresh does, and a token inside the grace window of a rotation still signs its
session out. A refusal is reported by `AuthenticationFailed` with the flow `sign_out` and its reason, and by no
`Failed`: a sign-out is not an attempt to authenticate. No attempt limit applies, since nothing is issued and a refresh
token cannot be guessed.

The `Sessions\SignOutResult` says whether this call revoked a session (`isSignedOut()`, `signedOut`), why the refresh
credential was refused when it was (`isFailed()`, `reason`), where it was read from (`source`), and, for a cookie
application, carries the expired cookie (`forgetCookie`), which `attachTo($response)` adds. It carries the cookie when
the access token signed its session out, which a cross-site page cannot send, and otherwise only when the request passes
the cookie's same-site checks (its `Origin` and the custom header, as a refresh from the cookie needs them) and was not
refused as `refresh_token_conflict`. So a cross-site page that auto-submits a form to the logout route clears nothing,
though a browser keeps a cookie the response to such a navigation sets, and a request that fails the checks leaves the
cookie in place with the session it still proves; a failed result is answered as a failure, as above.
`signOutWith($refreshToken)` signs out with a body application's token your code read itself, and forgets only a binding
to the session it revoked: a guard bound to another session stays bound to it, whether the token is refused or proves
another session. On a cookie application it throws a `LogicException`. `logout()` and `signOut()` cannot reach the
response either, so a route that calls them clears a cookie application's cookie with
`Auth::refreshTransport('browser')->forgetCookie()` only when `signOut()` returned `true` (or `Auth::check()` held
before `logout()`): a cross-site page cannot send the access token, but it can make a browser post to the route, and a
response that clears the cookie whatever the request carried lets any site sign the browser out. A route that must also
clear for a request without an access token checks `isSameSiteRequest($request)` first, or uses `signOutFromRequest()`,
which makes both checks (see [Refresh token cookie](refreshing.md#refresh-token-cookie)).

The session service also revokes sessions for the application's own screens and flows:

```php
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Facades\Auth;

$sessions = Auth::sessions('api');

// "Sign out of all other sessions": every session of the identity, of every guard, but this one.
$sessions->signOutEverywhere(keepCurrentSession: true);

// A session list's "sign out" button: only the identity's own session is found.
$sessions->revokeSession(Auth::identity(), $sessionId, RevocationReason::REVOKED);

// An administrator ends every session of an identity, or every session acting as a principal.
$sessions->revokeSessions($identity, RevocationReason::REVOKED, except: null);
$sessions->revokePrincipalSessions($membership, RevocationReason::REVOKED);
```

Each session is revoked by one conditional update that only applies while it is not revoked yet, so every call is
idempotent: the first revocation's time and reason are kept, and of two calls racing for a session only the one that
revoked it reports `SessionRevoked`. `revokeSession()` finds the session through the owner's `sessions()` relation on
the write connection, so another identity's session is simply not found and the call returns `false`, as it does for an
unknown or already revoked one. `revokeSessions()` covers every session the identity's relation returns, of every guard;
`revokePrincipalSessions()` every session of the configured model that records the principal. Both keep the `except`
session when one is given, and return how many sessions they revoked; pending sessions (waiting on a further factor or
a choice of principal) are sessions too, so their credentials stop working with them and none activates after the
revocation. `revokeSessions()` also cancels the identity's pending identifier changes, of every type and through
every guard: a change link needs no session, so one requested from a session that ends could otherwise still move the
account to an identifier of the requester's (see [Changing identifiers](identifier-changes.md)). `revokeSession()` and
`revokePrincipalSessions()` leave them, since the identity keeps its other sessions. `signOutEverywhere()` is
`revokeSessions()` for the request's identity with reason `signed_out_everywhere`; it returns `0` on a guest request,
and it leaves the guard bound for the rest of the request (call `signOut()` as well to end the current session too).
With `keepCurrentSession: true` on a request with an access-only token, which names no session, the token is kept by
leaving the identity's "tokens valid after" cutoff where it is, since a session-less token can only be ended through it:
every session is still revoked, but the identity's other session-less tokens keep working too, until they expire.

A bulk revocation first moves the scope's "tokens valid after" cutoff to now, when the identity or principal records one
(`HasTokensValidAfter`), then, in one transaction on the storage connection, revokes each unrevoked session, read on the
write connection in key order 500 at a time, pending ones included, and, for an identity, cancels its pending identifier
changes. Once that transaction commits, `SessionRevoked` reports each session it revoked (with the session's
own guard) and then `SignedOutEverywhere` reports the scope, with the acting guard, the reason, the count (also `0`, so
the action itself is recorded), the cutoff it set (or `null`), and the session it kept. If the session transaction
fails, the cutoff it already moved stands: more is cut off, never less, and calling again finishes the job. One window
stays open: a sign-in that has already passed its credential check when a bulk revocation reads the sessions can still
create its session afterwards. Closing it would take a lock that every sign-in and every revocation take on the
identity, which the package does not add. A sign-in that proves the client's previous session races a bulk revocation
the same way: when the revocation reads that session first, it is revoked with the bulk reason and the sign-in revokes
nothing and still creates its session; when the sign-in commits first, the previous session is already `superseded` (the
bulk call skips it) and the new session is revoked by the bulk call if its read finds it.

Called inside your own transaction on the storage connection, `revokeSessions()`, `revokePrincipalSessions()` and
`signOutEverywhere()` run as a savepoint there: the revocations commit or roll back with your change, and nothing is
reported until it commits. The cutoff moves on the identity's or principal's own connection, so it rolls back with them
only when that model lives on the storage connection too, as it must for a password reset:

```php
DB::transaction(function () use ($user) {
    $user->forceFill(['locked' => true])->save();

    Auth::sessions()->revokeSessions($user, RevocationReason::REVOKED);
});
```

### Signing in again

Every sign-in starts a new session; the previous session of the same client is not reused. A sign-in revokes the
client's previous session only when the client proves it holds it, with that session's current refresh token in the
`SignInContext` (see [Signing in](signing-in.md#signing-in-the-session-service)); the session is then revoked with the
reason `superseded` in the same transaction, and `SessionRevoked` reports it before the new session's `SessionCreated`.
The IP address and user agent never count, so an application that does not pass the refresh token keeps every earlier
session of the client until it expires, is signed out or is revoked. A refresh and a switch keep their
session.

### Listing sessions

`sessions()` returns one page of an identity's active sessions for a "where you're signed in" screen: every session it
holds on any guard that is active (not pending), not revoked and before its idle deadline and its absolute deadline
when it has one (each
summary's `absolute_expires_at` is `null` when it has none), most recently used first
(sessions never used last), then newest first:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;

Route::middleware('auth:api')->get('/sessions', fn () => Auth::sessions('api')->sessions(Auth::identity(), perPage: 20));
```

Each item is a `SessionSummary`, safe to return as it is: the session id (its `sid`), guard, sign-in method, client name
and platform, the creation time (for a model with Eloquent timestamps), IP address and user agent, when the session
started (the sign-in that created the session), the last use and its IP address and user agent, both deadlines, and
`current`, which marks the session the request is authenticated with on that guard. It never holds a refresh digest, the
rotation time, the revocation columns, the owner or the principal, and `toArray()` and JSON use snake_case keys and
ISO-8601 times. A page holds 1 to 100 sessions (15 by default; anything else is an `InvalidArgumentException`), and the
page is the request's `page` parameter unless you pass one. The list is read on the write connection through the
identity's `sessions()` relation, in two queries (a count and a select), so a session revoked a moment ago is never
shown. An identity that does not implement `HasSessions`, or whose `sessions()` relation queries a model that is not an
`EloquentSession`, is a `LogicException`.

`session()` gets one of them by its id, for a detail screen or before a "sign out" button revokes it:

```php
use SineMacula\Laravel\Authentication\Facades\Auth;

Route::middleware('auth:api')->get('/sessions/{session}', fn (string $session) => Auth::sessions('api')->session(Auth::identity(), $session) ?? abort(404));
```

It answers the very `SessionSummary` the list gives for that session, `current` marked the same way, or `null` when the
session is not the identity's, is not active (pending, revoked or past a deadline) or does not exist, without saying
which. It reads the identity's `sessions()` relation on the write connection with the list's rule, in one query, and an
id that cannot be a key of the session model (not a UUID, for the shipped model) is answered `null` without one, so
every session the list shows on any of its pages is found as it shows it, and no other. The identity must implement
`HasSessions`, as for the list.

The same rule is a query scope on any model that uses `ActsAsSession`, for your own queries:

```php
Session::query()->active()->where('guard', 'api')->count();
```

### Revoking on security changes

Call the session service from your own flows when something about an identity's security changes; each ends the
affected sessions (pending ones included) as a bulk revocation, with its own reason, moves the scope's cutoff, and, for
the four that end an identity's sessions, cancels its pending identifier changes:

| Method                                             | Ends                                                        | Reason                  |
|----------------------------------------------------|-------------------------------------------------------------|-------------------------|
| `passwordChanged($identity, ?Session $except)`     | The identity's sessions, but `$except`                      | `password_changed`      |
| `passwordReset($identity)`                         | Every session of the identity                               | `password_reset`        |
| `credentialRemoved($identity, ?Session $except)`   | The identity's sessions, but `$except`                      | `factor_removed`        |
| `identityDeactivated($identity)`                   | Every session of the identity                               | `identity_deactivated`  |
| `principalDeactivated($principal)`                 | Every session acting as the principal                       | `principal_deactivated` |
| `tenantDeactivated($tenant, iterable $principals)` | Every session acting as a listed principal or in the tenant | `tenant_deactivated`    |

Never call `passwordChanged()` for the automatic rehash of a password on sign-in: the password did not change. These
methods end sessions and pending identifier changes only. A change or a reset set through `Auth::passwords()->set()`
(see [Setting a password](passwords.md#setting-a-password)) calls them and also ends the other proofs that could take
the account back without a session: the reset links and codes and the sign-in codes of the identity. A registration
calls none of them and ends only the reset links and codes. A password your own flow saves another way leaves those
proofs as they are. `credentialRemoved()` is for a first-factor credential the identity removed (a passkey, or a phone
number or email address it signs in with); a factor of the factor package's has its own triggers (see [Sign-in
factors](#sign-in-factors)). The tenant's principals are yours to list, so `tenantDeactivated()` takes them from you (it
also ends every session acting in the tenant, whatever its principal): each must act within the tenant (read on the
write connection from the principal as stored, so a `tenant` relation you loaded does not decide and Eloquent's strict
mode does not stop the read), or an `InvalidArgumentException` is thrown before anything is written. A `CanBeActive`
tenant already deleted or soft-deleted still works, since a principal whose `TenantUnavailableException` names that very
tenant (its class and key, as `ActsAsPrincipal` reports it) acts within it, so restoring the tenant later revives no
session; a tenant that does not implement `CanBeActive` reads as no tenant once it cannot be loaded, so call
`tenantDeactivated()` before deleting it; a principal listed twice counts once, and every principal's sessions end in
one transaction on the storage connection, with one `SignedOutEverywhere` per principal. Deactivation already stops
every token at once through the live activity checks (see [Active-state
enforcement](identity-models.md#active-state-enforcement)); revoking makes the end outlast a reactivation and records
why.

Three optional listeners call them for you. Registering one is the opt-in, and each revokes only once the change that
triggered it is committed on the changed model's connection, so a change that is rolled back revokes nothing:

```php
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Facades\Event;
use SineMacula\Laravel\Authentication\Listeners\RevokeSessionsOnDeactivation;
use SineMacula\Laravel\Authentication\Listeners\RevokeSessionsOnPasswordChange;
use SineMacula\Laravel\Authentication\Listeners\RevokeSessionsOnPasswordReset;

Event::listen(PasswordReset::class, RevokeSessionsOnPasswordReset::class);
User::observe(RevokeSessionsOnPasswordChange::class);
User::observe(RevokeSessionsOnDeactivation::class);
Membership::observe(RevokeSessionsOnDeactivation::class);
```

- `RevokeSessionsOnPasswordReset` answers Laravel's `PasswordReset` (the password broker's) with `passwordReset()`.
- `RevokeSessionsOnPasswordChange` observes an identity model and answers a saved change of its password column with
  `passwordChanged()`, revoking every session, the one the change was made from included; to keep that one, call
  `passwordChanged($identity, Auth::session())` yourself instead. The automatic rehash on sign-in is not a change, and
  the observer ignores it: the package's own sign-ins run it marked, and so do Laravel's guards (`attempt()`,
  `attemptWhen()`, `once()`, as a web login over the same user model does), whose attempt the package follows through
  Laravel's auth events. A save is the rehash only when it re-encodes the password signed in with (both the hash it
  replaces and the hash it saves verify it) and no change of the user's password has run since the rehash or attempt
  began; for an attempt, it must also save the very model instance the attempt validated. So a new password saved before
  the attempt ends (by an `attemptWhen()` callback, say) revokes, and so does any later save of the user, a change back
  to that password or a fresh hash of it through another instance included. An attempt made inside another attempt's
  callback, or the session's user resolved there, leaves the outer attempt's rehash alone; two cases end the outer
  attempt early, so its rehash then revokes: an `Auth::login()` of the very instance it validated inside its callback,
  and a refused inner attempt that validated that same instance (from a provider that caches its users). Users are told
  apart by the row they are stored in (connection, database, table and key), so the same key in another tenant's
  database is another user. Confirming the current password with `validate()` before changing it is not an attempt, so
  the change that follows revokes; so does Laravel's `logoutOtherDevices()`, whose forced rehash exists to sign the
  other sessions out, even while an attempt for the user is open or the package's own rehash runs: the package holds a
  save it takes for a rehash until the request or job ends, and the `OtherDeviceLogout` event that follows a forced
  rehash runs it, so a sign-out after an attempt's rehash in the same request may revoke twice. Only changes saved
  through Eloquent fire model events.
- `RevokeSessionsOnDeactivation` observes a `CanBeActive` identity or principal model and answers an update that turns
  it from active to inactive with `identityDeactivated()` or `principalDeactivated()` (a 2D model is treated as the
  identity). It compares a copy holding the attributes from before the update with the model as it is now, so it suits
  activity held in the model's own attributes (`ProvidesActiveState`); for activity derived from anything else, call the
  method yourself. A tenant has no listener: its principals are yours to list, so call `tenantDeactivated()` with them
  (it also ends every session acting in the tenant). Registering the observer on a model that is neither an identity nor
  a principal throws a `LogicException` when that model is deactivated.

A password reset through Laravel's broker saves the new password through Eloquent before your code fires
`PasswordReset`, so with both password listeners registered the observer revokes every session first, as
`password_changed`, and the reset listener then finds none left to revoke (its `SignedOutEverywhere` reports
`password_reset` with a count of `0`). Register one of them for each flow: the observer alone ends sessions on every
change of password, resets included, as `password_changed`; to record resets as `password_reset`, register the reset
listener and call `passwordChanged()` from your password-change flow instead of registering the observer.

Revocation covers every guard whichever session service acts; the acting guard only names the guard and request the
events report. It is the current default guard when that is a `jwt` guard, else the first `jwt` guard in
`auth.guards`, so a change made on a route guarded by another driver (whose middleware makes that guard the default)
still revokes. To name it, bind the listener's `$guard`:

```php
$this->app->when(RevokeSessionsOnPasswordChange::class)->needs('$guard')->give('api');
```

With no `jwt` guard configured at all, a listener throws an `InvalidArgumentException`.

### Sign-in factors

A sign-in factor is anything the identity signs in with: a first-factor credential (a passkey, or a phone number or
email address it signs in with) or one of the factor package's further factors. A removed first-factor credential is
yours to answer, per event, with `credentialRemoved()` or `RevokeSessionsOnPasskeyRemoval` (see above). The factor
package's two triggers are mandatory: no setting turns them off, and the factor package calls them itself, inside the
transaction that makes its change and after its own locks, never through a listener:

| Method                                                        | Ends                                                                                  | Reason           |
|---------------------------------------------------------------|---------------------------------------------------------------------------------------|------------------|
| `factorRemoved($identity, string $factor, ?Session $current)` | The identity's sessions, pending ones included, but `$current`, which is judged again | `factor_removed` |
| `factorReset($identity)`                                      | Every session of the identity, the current one included                               | `factor_reset`   |

```php
DB::transaction(function () use ($user, $factor) {
    $factor->newQuery()->whereKey($factor->getKey())->lockForUpdate()->first();
    $factor->delete();

    $removal = Auth::sessions()->factorRemoved($user, $factor->reference(), Auth::session());

    if ($removal->isPending()) {
        // Hand $removal->credential to the client in the response body.
    }
});
```

`$factor` is the factor package's reference to the factor, 1 to 255 characters. `$current`, the session the removal was
made from, is judged again without the factor: the proofs it made with that factor are voided, so they never count
again, and then:

- it stays active while it still meets the identity's factor policy and its tenant's policy, with another factor say;
- it returns to pending, waiting on a further factor (`SessionReturnedToPending`, flow `factor_change`), while that is
  all it falls short of: its access and refresh tokens stop at once, and `FactorRemoval::$pending` and
  `$credential` carry what a client needs to satisfy it again;
- it is revoked (`factor_removed`) when it is no longer admitted as a refresh admits it (its identity, principal or
  tenant inactive or ineligible) or its tenant now requires a connection: nothing it could do in place would meet it.

A current session that is pending has its proofs made with the factor voided too and stays pending: its next action
(`satisfy()`, `choose()`) is judged without them. One that was meanwhile revoked or ended is left as it is. When the
request's guard is bound to the current session and it returned to pending or was revoked, the guard forgets it once the
transaction commits, before anything is reported, so the rest of the request is no longer authenticated as it, even when
a listener throws. `factorReset()`, and `factorRemoved()` given no `$current`, do the same for a guard bound to the
identity: every session it has ends, so the rest of the request is not authenticated as any of them.
`FactorRemoval::$revoked` counts the sessions revoked, the current one included when it was (`$currentRevoked`).
`$current`, when given, must be a session of this guard the identity owns, and the identity must live on the storage
connection, so its cutoff moves and its sessions end in the factor package's transaction: otherwise nothing is written
and an `InvalidArgumentException` or a `LogicException` is thrown. Everything runs in one transaction on the storage
connection, a savepoint in the factor package's, and is reported once that commits.

A passkey the factor package associated as a factor is removed through `PasskeyService::remove()`, which asks the factor
package first, and the factor package then calls `factorRemoved()`. `RevokeSessionsOnPasskeyRemoval` still ends every
session on any passkey's removal, the current one included, once committed: with the factor package, register it only
if that is what you want.

### Connections and links

When an external provider's connection is disabled or deleted, or one of an identity's links through it is removed or
has its scope widened, end the sessions it established from the same transaction:

```php
DB::transaction(function () use ($connection) {
    $connection->update(['enabled' => false]);

    Auth::sessions()->connectionDisabled($connection->id);
});

Auth::sessions()->connectionDeleted($connectionId);
Auth::sessions()->linkRemoved($user, $connectionId, $linkId);
Auth::sessions()->linkScopeWidened($user, $connectionId, $linkId);
```

`connectionDisabled()` and `connectionDeleted()` revoke every live session whose provenance records the connection (of
every guard and identity, pending ones included; one already past a deadline is left for pruning), as
`connection_disabled` or `connection_deleted`. `linkRemoved()` and `linkScopeWidened()` revoke only the identity's
sessions established through that one link: the provenance must record both the connection and the link id the link
contract answered when the session was established, so the identity's sessions through its other links, of the same
connection or another, stay, and a session recorded with no link is never one of a link's. They revoke as `link_removed`
and `link_scope_widened`. Each returns how many it revoked. They are found through the provenance's connection index (a
link's through the identity's sessions, then their provenance by key) 500 at a time, each chunk locked in key order, in
one transaction on the storage connection, a savepoint inside yours. Both are found with locking reads, so a session a
sign-in through the connection or link committed while your transaction waited for your lock on it is found even on
MySQL's REPEATABLE READ, where a plain read would see your transaction's first snapshot. A link's read takes only the
identity's sessions under `external_provider`, each of which has a provenance, so on MySQL it locks those rows (until
your transaction ends) and no gap another identity's sign-in would write into. Once that commits, a request's guard
bound to one of them forgets it, so the rest of the request is not authenticated as it even when a listener throws, and
then `SessionRevoked` reports each. No cutoff moves and no `SignedOutEverywhere` is reported: the scope is how the
sessions began, not the identity, whose other sessions stay.

On PostgreSQL at REPEATABLE READ or SERIALIZABLE even a locking read sees only your transaction's first snapshot, so a
session a sign-in committed after it would be invisible. A sign-in through a link therefore writes its link's guard (one
of 64 rows per connection, in `proofs.guards_table`) before it writes the session, and before reading anything a link's
revocation writes that guard and a connection's revocation every guard of the connection. When the sign-in committed
after your transaction's snapshot was taken, the revocation fails to serialise (SQLSTATE 40001, raised by Laravel as an
`Illuminate\Database\DeadlockException` inside your transaction) rather than miss the session: roll back and retry the
whole transaction, as you do for any serialisation failure there, and the retry's snapshot sees the session and ends it.
A sign-in whose transaction read before a revocation committed fails the same way. At READ COMMITTED, and on MySQL at
any level, the guard only makes the later of the two wait for the earlier, and the locking reads find the session. Two
sign-ins through different links of one connection share a guard about once in 64 times, and a connection's revocation
holds every guard of the connection until your transaction ends, so sign-ins through it wait for that.

`connectionDisabled()`, `connectionDeleted()` and `linkRemoved()` are on by default and each turned off by its
`authentication.revocation.*` setting (see [Revocation by connection](configuration.md#revocation-by-connection)).
`linkScopeWidened()` is mandatory, as `tenantPolicyChanged()` is: no setting turns it off, since a link that may now act
for more than its sessions were established for must not keep them. Call it synchronously in the transaction that widens
the scope; calling it twice for one widening is safe, as the second call finds nothing live left to end and revokes and
reports nothing. A connection or link id may not be empty. Both are matched byte for byte, so revoking one never ends
the sessions of another whose id differs from it only in case, accents or a trailing space.

### Access tokens without a session

An access token issued without a session (access-only mode, see
[Access-only mode](installation.md#access-only-mode-no-sessions-no-refresh)) has no session to revoke. To end those too,
an identity or principal implements `HasTokensValidAfter`, with the `ProvidesTokensValidAfter` trait over a nullable
whole-second column you add:

```php
Schema::table('users', function (Blueprint $table) {
    $table->dateTime('tokens_valid_after', 0)->nullable();
});
```

```php
use SineMacula\Laravel\Authentication\Concerns\ProvidesTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;

class User extends Model implements HasTokensValidAfter, Identity, Principal
{
    use ProvidesTokensValidAfter;
}
```

Every bulk revocation of its sessions (including the security-change methods above) then moves its cutoff to the
revocation's second first, except `signOutEverywhere(keepCurrentSession: true)` from an access-only token, which
keeps the identity's cutoff where it is (see above), and the bearer path rejects a session-less access token whose `iat`
is at or before the identity's or the principal's cutoff (`issued_before_cutoff`). The whole second is cut off, because
a token's whole-second `iat` cannot tell an earlier token from one issued after the call in the same second, so a
session-less token issued in that second is rejected too. Tokens that name a session are not checked against the cutoff
(revoking the session ends them, and the session a sign-out everywhere keeps must keep working). The cutoff only ever
moves forward, with one conditional update on the model's own connection (`invalidateTokensIssuedBefore()`); the column
must be loaded, or reading it throws a `LogicException`, and the column name comes from `getTokensValidAfterName()`.

### Tenant authentication policies

A tenant may ask more of the sessions active in it than the identity's own sign-in did: a further factor, or a sign-in
through one of its connections (single sign-on). The package asks the bound `Contracts\TenantAuthenticationPolicy` (the
default, `RequireNothingOfTenants`, asks nothing; see
[Tenant authentication policies](extending.md#tenant-authentication-policies)) whenever a session comes to act in a
tenant or keeps acting in it: at sign-in once a principal is selected, at a choice of principal, when a pending session
activates, at every refresh, for the destination of a switch, when `Auth::caller()` reads a refresh credential, and at a
reauthentication at the external provider (`reauthenticateExternally()`), never on a bearer request. A session that
falls short:

| Where                                 | Needs a connection                                                       | Lacks a further factor                                                   |
|---------------------------------------|--------------------------------------------------------------------------|--------------------------------------------------------------------------|
| Sign-in                               | refused as `sso_required`, nothing written                               | written pending on `mfa`                                                 |
| Choice of principal                   | that principal refused as `sso_required`, the session stays pending      | the principal recorded, the session pending on `mfa`                     |
| Satisfying a further factor           | refused as `sso_required`, the session stays pending until it expires    | stays pending                                                            |
| Refresh                               | refused as `sso_required`, the session revoked (`tenant_policy_changed`) | returned to pending: the result `isPending()`, with a pending credential |
| Switch                                | refused as `sso_required`, the session unchanged                         | returned to pending with the destination recorded, as for a refresh      |
| `attempt()`                           | refused as `sso_required`                                                | refused as `additional_factor_required`                                  |
| The caller of a refresh credential    | no caller (`sso_required`), nothing written                              | no caller (`additional_factor_required`), nothing written                |
| External reauthentication             | refused as `sso_required`, the proof rolled back, nothing written        | refused as `additional_factor_required`, the proof rolled back           |

A further factor is met only as the bound `Contracts\ExternalEvidencePolicy` judges an external provider's accepted
evidence (see [Proofs and provenance](#proofs-and-provenance)) or the bound `Contracts\RequirementCheck` judges the
session's proofs (the defaults, `InsufficientEvidence` and `MeetNoRequirement`, meet nothing, so a tenant that requires
a further factor admits no session until the application trusts a provider's evidence or a factor package binds its
check). A session established through a connection carries it in its provenance (`signInExternally()`). A
session that meets the policy records the version of the answer in `tenant_policy_version`.

A refresh that returns a session to pending hands out no pair: `RefreshResult::isPending()`, with `pending` (what it
waits on, `["mfa"]`) and `credential`, and `SessionReturnedToPending` reports it. A guard the request already bound to
that session forgets it, with no event, as a switch's return does, so nothing later in the request acts in it. From then
on the session's access tokens and its refresh token are refused (`session_pending`, never taken for a replay), until
the factor is satisfied with `Auth::sessions()->satisfy($credential, $proof)` (see [Pending
sessions](signing-in.md#pending-sessions)): the session activates again in place, same id and proofs, with a new pair,
`SessionActivated` reports it, and every token issued before the return stays refused.

When a tenant's policy changes, call the helper, which revokes the sessions that no longer meet it at once:

```php
DB::transaction(function () use ($tenant, $policy) {
    $policy->save();

    Auth::sessions('api')->tenantPolicyChanged($tenant);
});
```

The helper is mandatory: no setting turns it off, and nothing calls it for you. It reads the tenant's live sessions
(`tenant_id`, every guard, pending ones included; one already past a deadline is left for pruning) on the storage
connection in key order, a chunk at a time, each chunk under a lock; skips a session recorded at the very version the
policy now answers (neither `null`); revokes an active one that no longer meets it as `tenant_policy_changed`, and a
pending one only when it would need another connection (a pending one that lacks a factor is judged when it activates);
and records the version on an active one that meets it. It returns how many it revoked, and `SessionRevoked` reports
each once committed. Call it inside the transaction that publishes the change, on the storage connection, so the two
commit or roll back together (it runs as a savepoint and never commits on its own), and, for a strict cut-off, once more
after that transaction commits: a session that entered the tenant while the first call ran is then judged too. Change
the policy's version whenever anything its answer depends on changes, so the helper never skips a session it should
judge.

### Revocation reasons

Every revocation records one of these reasons in the session's `revoked_reason` and in `SessionRevoked::$reason`
(`RevocationReason`); a bulk revocation reports it in `SignedOutEverywhere::$reason` as well:

| Reason                  | Recorded when                                                                                                                              |
|-------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|
| `signed_out`            | The session signed itself out: `logout()`, `Auth::sessions()->signOut()`, `signOutFromRequest()`, `signOutWith()`                          |
| `signed_out_everywhere` | `signOutEverywhere()` ended the identity's sessions                                                                                        |
| `revoked`               | The application revoked it: `revokeSession()`, `revokeSessions()`, `revokePrincipalSessions()`                                             |
| `rotation_reuse`        | A rotated refresh token was replayed, by a refresh, a switch, a sign-out or the caller of a refresh credential                             |
| `superseded`            | A sign-in that proved the client holds the session, with its current refresh token, replaced it with a new session                         |
| `password_changed`      | `passwordChanged()`: directly, through `Auth::passwords()->change()` or `set()` with `CHANGE`, or through `RevokeSessionsOnPasswordChange` |
| `password_reset`        | `passwordReset()`: directly, through a reset or `set()` with `RESET`, or through `RevokeSessionsOnPasswordReset`                           |
| `password_established`  | `Auth::passwords()->establish()`: the identity's other sessions once it established its first password                                     |
| `factor_removed`        | `credentialRemoved()`, directly or through `RevokeSessionsOnPasskeyRemoval`, or the factor package's `factorRemoved()`                     |
| `identity_deactivated`  | `identityDeactivated()`, directly or through `RevokeSessionsOnDeactivation`                                                                |
| `principal_deactivated` | `principalDeactivated()`, directly or through `RevokeSessionsOnDeactivation`                                                               |
| `tenant_deactivated`    | `tenantDeactivated()`                                                                                                                      |
| `tenant_policy_changed` | `tenantPolicyChanged()`, or a refresh that finds the tenant now requires a connection the session was not established through              |
| `factor_reset`          | The factor package's `factorReset()`: every session of the identity                                                                        |
| `connection_disabled`   | `connectionDisabled()`: the sessions the connection established                                                                            |
| `connection_deleted`    | `connectionDeleted()`: the sessions the connection established                                                                             |
| `link_removed`          | `linkRemoved()`: the identity's sessions established through the link                                                                      |
| `link_scope_widened`    | `linkScopeWidened()`: the identity's sessions established through the link, mandatory                                                      |

`revokeSession()`, `revokeSessions()` and `revokePrincipalSessions()` take the reason as an argument (`REVOKED` in the
examples above); the others set their own.

## The caller of a request

`Auth::caller()` answers who the request being served is, as the credential its route authenticates with proves it: a
`Callers\Caller` with the `guard`, the `credential` it was read from (`CallerCredential::ACCESS`, `REFRESH` or
`PENDING`), the `identity`, and the `principal`, `tenant` and `session` that credential holds, with the `pending`
session a pending credential names; or `null` when the request carries no such credential or it is refused. An
access-only token or an API key holds no session, and a pending session that waits for the choice acts as no principal
yet.

A route authenticates with the access credential of its guard (the one `auth:<guard>` makes the default) unless it
declares another. `authentication.refresh[:<guard>]` declares the refresh credential: the one the guard's refresh token
transport reads (see [Refreshing](refreshing.md)), proven and admitted as a refresh would be, without rotating it, and
judged against the tenant's authentication policy as a refresh judges it, without writing: a session the next refresh
would revoke has no caller (`sso_required`), nor does one it would return to pending (`additional_factor_required`). A
replayed refresh token revokes its session as `rotation_reuse`, as a refresh does, so a read route behind
`authentication.refresh` can revoke one. A cookie application's route lives under its cookie's path, where the browser
sends the cookie. `authentication.pending:<action>[,<guard>]` declares the pending credential for a pending action by
its stable name (`mfa.verify`, `choose_principal`, ...), read from the `session.pending_credential_field` body field
(`pending_credential`; a JSON or form body, never the query string or a header): there is a caller only while it names a
live pending session of the guard that allows that action now, and the operation the route then takes (`satisfy()`,
`choose()`, an adapter's action after `pending()`) makes its own checks. An action that is not a pending action is an
`InvalidArgumentException`. Each makes a guard it names the default for the request, as `auth:<guard>` does, and records
the declaration, nothing else: the credential is never inferred from what a request carries, so a refresh cookie that
rides on every request does not turn a read route into one a refresh token authenticates. The package orders both before
`SubstituteBindings` in the HTTP kernel's middleware priority once the kernel is resolved, so the declaration is in
place before any route parameter is bound however a route lists them, also when the application sets the whole list with
`withMiddleware()`'s `priority()`, as long as that list holds `SubstituteBindings`; one that replaces the list later
must put `SineMacula\Laravel\Authentication\Http\Middleware\UseRefreshCredential` and `UsePendingCredential` before
`SubstituteBindings` itself.

The caller is read only when it is asked for, and once per request for a guard and a credential, so asking twice proves
a refresh credential once. A refresh or pending credential the request carries and that is refused is reported once with
`AuthenticationFailed`: flow `refresh` with the reason the refresh would give (`additional_factor_required` where the
refresh would return the session to pending), or flow `sign_in` with `pending_invalid` or `pending_action_not_allowed`,
never the credential; a request that carries none is not reported. A guard that is not one of the package's is a
`LogicException`.

`$caller->owns($model)` says whether a session, identity or principal model is the caller's: a session of the caller's
guard that its identity owns and, for a refresh or a pending credential, the very session the credential proves (with
the access credential any session of the identity on that guard, so a screen can revoke another one); the caller's
identity; or the principal it acts as, one its pending session offers for the choice, or, for a guard that keeps
sessions, one its identity may use the application as (`Auth::sessions()->principal()`, with the type of identifier its
session's sign-in used, read on the write connection). Each is judged by its class and key, and any other model is not
the caller's. It judges the model as it is given, so look the model up on the write connection
(`Database\WriteConnection`), where a revocation or a deletion the replica has not seen yet is already visible.

The package binds no route parameter and reserves no keyword: the word that means the caller's own (`me`, `self`,
`current`), and how a model binds, are the application's. An application that wants `current` for the caller's own
session, and every other id scoped to the caller, might bind its own:

```php
use Illuminate\Auth\AuthenticationException;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\Session;

Route::bind('session', function (string $value): Session {
    $caller = Auth::caller() ?? throw new AuthenticationException;

    if ($value === 'current') {
        return $caller->session instanceof Session ? $caller->session : abort(404);
    }

    $session = WriteConnection::query(Session::query())->find($value);

    return $session instanceof Session && $caller->owns($session) ? $session : abort(404);
});

Route::middleware('auth:api')->get('/sessions/{session}', fn (Session $session) => $session);
Route::middleware('authentication.refresh:api')->post('/auth/sessions/{session}', fn (Session $session) => $session);
```

A request without a caller is an `AuthenticationException`, which the package's guards answer `401` as JSON.
