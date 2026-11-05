<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\GuardBinding;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\Concerns\EndsConnectionSessions;
use SineMacula\Laravel\Authentication\Sessions\Concerns\EndsSessions;
use SineMacula\Laravel\Authentication\Sessions\Concerns\GatesFactorChanges;
use SineMacula\Laravel\Authentication\Sessions\Concerns\LooksUpSessions;
use SineMacula\Laravel\Authentication\Sessions\Concerns\ProvesSessions;
use SineMacula\Laravel\Authentication\Sessions\Concerns\RefreshesSessions;
use SineMacula\Laravel\Authentication\Sessions\Concerns\SignsInExternally;
use SineMacula\Laravel\Authentication\Sessions\Concerns\SwitchesSessions;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;

/**
 * The session service of a JWT guard: signs in, creates the session, issues the
 * first token pair, and binds the guard, in one call; or leaves the session
 * pending, with a pending credential, while it waits on requirements.
 *
 * `signIn()` verifies the input with a sign-in method; `start()` begins a
 * session for an identity something else verified; `signInExternally()` begins
 * one for the identity a result an external identity provider verified is
 * linked to (`SignsInExternally`). Each way, in the order sign-in takes: the
 * application policy must allow the method; the identity must be human, active
 * and admitted with the identifier type the sign-in used; the principals the
 * application admits are found (with none left the sign-in is refused, after
 * the credential is verified); the one named, or the only one, is selected, or
 * a choice is left outstanding; the identity-level factor policy is asked,
 * before any principal is chosen; a selected principal's active tenant is
 * admitted; and that tenant's authentication policy is asked: one requiring
 * sign-in through a connection the sign-in did not come through refuses it
 * (`sso_required`), and a further factor it requires is outstanding as the
 * identity's own is. With nothing outstanding the session starts active;
 * otherwise it is pending (`SignInResult::pending()`), waiting on the further
 * factor, then the choice, and holding no token. `pending()` reads a pending
 * session for an action, `satisfy()` hands it the proof of a further factor,
 * `choose()` makes the choice, and `discard()` ends it; each takes the pending
 * credential, which travels only in a response body. `satisfy()` and `choose()`
 * judge the client they are given, or the guard's request's.
 *
 * Every sign-in creates a new session, which records the proof of its first
 * factor (and the provenance of a session an external provider established) in
 * the same transaction, and every further factor `satisfy()` is given; the
 * access token's `auth_time` and `amr` are derived from those proofs. A client
 * that proves, with its refresh token, that it holds a session of this guard
 * for the same identity and principal has that session revoked (`superseded`)
 * when the new one starts active; nothing else is revoked, however alike the IP
 * address or user agent are.
 *
 * The session is established by `SessionEstablishment`, which writes it and
 * schedules what reports it but never binds; the service binds the guard only
 * once that has returned, and only once the session's writes commit, so a
 * sign-in inside a caller's transaction that rolls back never binds. Pending
 * sessions are acted on through `PendingSessions`. The service also refreshes a
 * session through `SessionRefresh` (`RefreshesSessions`), steps a session up
 * and reauthenticates it through `SessionStepUp` and `SessionReauthentication`
 * (`ProvesSessions`), or at an external provider through the link that
 * established it through `ExternalReauthentication` (`SignsInExternally`), each
 * of which issues a new access token only, gates the factor package's changes
 * to an identity's further factors through `FactorChangeGate`
 * (`GatesFactorChanges`), lets a session switch the principal it acts as or its
 * active tenant through `SessionSwitch` (`SwitchesSessions`), lists sessions,
 * looks one session or principal, or an active session's proofs and first
 * factor, up (`LooksUpSessions`), and signs out, revokes sessions and ends
 * sessions on security changes through `SessionRevocations` (`EndsSessions`),
 * which the guard's `logout()` and password changes use too, judges the current
 * session again after the factor package's changes through `FactorRevocations`,
 * signs out by refresh credential through `SessionSignOut`, and ends the
 * sessions a connection established through `ConnectionRevocations`
 * (`EndsConnectionSessions`).
 *
 * Failures are results, not exceptions: Laravel's `Failed` and the package's
 * `AuthenticationFailed` report them. Exceptions are kept for misconfiguration
 * and server errors. The service keeps no state between calls: it runs on the
 * guard's context, reading its provider, resolver, dispatcher and request, and
 * the sign-in policies bound in the container, each time it needs them, and
 * reaches the guard's bound state only through the binding it is given. The
 * auth manager builds one on each call of `Auth::sessions()`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SessionService
{
    use EndsConnectionSessions, EndsSessions, GatesFactorChanges, LooksUpSessions, ProvesSessions, RefreshesSessions, SignsInExternally, SwitchesSessions;

    /** @var \SineMacula\Laravel\Authentication\Sessions\SessionEstablishment Takes an admitted sign-in to its session, active or pending, never binding. */
    private SessionEstablishment $establishment;

    /** @var \SineMacula\Laravel\Authentication\Sessions\PendingEvaluation The checks a sign-in passes, and the principals an identity may use. */
    private PendingEvaluation $evaluation;

    /** @var \SineMacula\Laravel\Authentication\Sessions\PendingSessions Reads, satisfies, chooses for and discards pending sessions. */
    private PendingSessions $pendings;

    /** @var \SineMacula\Laravel\Authentication\Database\AfterCommit Defers the report of a switch or a refresh until it commits. */
    private AfterCommit $afterCommit;

    /** @var \SineMacula\Laravel\Authentication\Sessions\DeferredBind Binds the guard to a signed-in, refreshed or switched session once it commits. */
    private DeferredBind $binds;

    /** @var \SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore The guarded switch write and its locking re-read. */
    private RefreshRotationStore $rotations;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Contracts\GuardBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     * @param  \Closure(): mixed  $transactions
     */
    public function __construct(

        /** The context of the guard whose sessions the service starts. */
        private GuardContext $context,

        /** The guard's bound state, which a sign-in, a switch and a sign-out act on. */
        private GuardBinding $binding,

        /** The guard's token service, which a refresh and a switch parse and issue with. */
        private JwtTokenService $tokens,

        /** Container the sign-in methods and policies are resolved from. */
        private Container $container,

        // Resolver for the session's own connection.
        ConnectionResolverInterface $connections,

        // Returns the current transactions manager, if any, when called.
        \Closure $transactions,
    ) {
        $sessions        = new RevocationWriter($connections, $transactions);
        $externalResults = new ExternalResults($context, $container);
        $proof           = new ProvenSessions($tokens);
        $writer          = new SessionWriter($context->name(), $tokens, $connections);

        $this->afterCommit       = new AfterCommit($transactions);
        $this->binds             = new DeferredBind($context, $this->afterCommit);
        $this->rotations         = new RefreshRotationStore($connections);
        $this->evaluation        = new PendingEvaluation($context, $container);
        $this->externalSignIns   = new ExternalSignIn($externalResults, $this->evaluation);
        $this->establishment     = new SessionEstablishment($context, $writer, $proof, $this->evaluation, $this->afterCommit, $container);
        $activation              = new SessionActivation($context, $tokens, $this->afterCommit, $container);
        $this->pendings          = new PendingSessions($context, $this->evaluation, $activation, $sessions, $this->afterCommit);
        $this->revocations       = new SessionRevocations($context, $sessions, $container);
        $this->policyChanges     = new TenantPolicyChanges($context, $this->afterCommit);
        $this->switchRevocations = $sessions;
        $this->transitions       = new PendingTransitions($context, $this->afterCommit, $container->make(Repository::class));

        $refreshProof = new RefreshProof($context, $tokens, $this->rotations, $this->afterCommit);
        $exchange     = new RefreshTokenExchange($tokens, $context, $connections, $transactions);

        $this->refreshes = new SessionRefresh($context, $binding, $exchange, $this->afterCommit, $this->binds, $container, $refreshProof);
        $this->signOuts  = new SessionSignOut($context, $binding, $this->revocations, $sessions, $refreshProof, $container);

        $this->connectionRevocations = new ConnectionRevocations($context, $binding, $sessions, $this->afterCommit, $container);
        $this->factorRevocations     = new FactorRevocations(
            $context,
            $binding,
            $this->revocations,
            $sessions,
            $this->transitions,
            $container,
        );

        $issuance = new ProofIssuance($context, $tokens, $this->afterCommit);

        $this->stepUps           = new SessionStepUp($context, $issuance, $this->afterCommit);
        $this->reauthentications = new SessionReauthentication($context, $issuance, $this->afterCommit, $container);

        $this->externalReauthentications = new ExternalReauthentication($context, $issuance, $externalResults, $this->evaluation, $this->afterCommit);
        $this->factorChanges             = new FactorChangeGate($context, $container);
    }

    /**
     * Sign in with the named sign-in method and the input the client sent.
     *
     * In order: Laravel's `Attempting` (with only the identifier the input
     * names, never the input itself); a cookie application's request must come
     * from a page of its own site (`cross_site_request`, before anything is
     * read, counted or written: see
     * `RefreshTokenTransport::isSameSiteClient()`, judged on the context's
     * client, the guard request's unless a context is given); the application
     * policy must allow the method (`method_not_allowed`, nothing counted); the
     * identifier and the client's IP address must have attempts left
     * (`rate_limited`); then, inside the credential timebox, the method must
     * verify the input (its `FirstFactor` is the session's first proof, timed
     * when it returned) and the identity must be human, active and admitted
     * with the identifier type the input used. Then the sign-in follows the
     * order the service describes: a deadline the context supplies that has
     * already passed fails as `session_expired`; the principal the context
     * names, or the only one the application admits, is selected, or a choice
     * is left outstanding (with none left, the sign-in fails with the reason
     * the last was refused, or `principal_unresolved`); a password is rehashed
     * when its hash is outdated; the client's refresh token, if any, is checked
     * as proof of an existing session; the identity-level factor policy is
     * asked; a selected principal's tenant (the context's, or its own) is
     * admitted; and that tenant's authentication policy is asked, judged
     * against the sign-in's own proof and provenance: one requiring sign-in
     * through a connection the sign-in did not come through fails it as
     * `sso_required`, writing nothing, and a further factor it requires is
     * outstanding as the identity's own is. With nothing outstanding the
     * session starts and the sign-in gives back the attempt's slots and those
     * the method took on the accounts it checked; otherwise the session is
     * pending and keeps them all until it first activates.
     *
     * @param  string  $method
     * @param  array<array-key, mixed>  $input
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    public function signIn(string $method, #[\SensitiveParameter] array $input, ?SignInContext $context = null): SignInResult
    {
        $transport = $this->transport();
        $driver    = $this->container->make(SignInMethodManager::class)->method($method);
        $context ??= SignInContext::fromRequest($this->context->request());
        $type       = $driver->identifierType($this->context->name());
        $identifier = $driver->identifier($this->context->name(), $input);
        $safe       = $identifier === null ? [] : [$type ?? 'identifier' => $identifier];

        $this->context->dispatch(new Attempting($this->context->name(), $safe, false));

        $subject = new AttemptSubject($this->context->name(), AttemptFlow::SIGN_IN, $identifier, $type, $context->client->ip);
        $outcome = SessionPreconditions::crossSite($transport, $context->client) ?? $this->signInWith($driver, $method, $input, $context, $subject, $transport);

        if (!$outcome instanceof Refused) {
            return $outcome;
        }

        $unanswered = in_array($outcome->reason, [FailureReason::METHOD_NOT_ALLOWED, FailureReason::CROSS_SITE_REQUEST], true);

        return $this->fail($outcome, $method, $context, $identifier, $safe, $unanswered ? null : $driver->challenge($input));
    }

    /**
     * Start a session for an identity verified outside the guard, through the
     * named method.
     *
     * A cookie application's request must come from a page of its own site, as
     * `signIn()`'s must (`cross_site_request`, before the identity is
     * reloaded): an application whose own verification arrives as a cross-site
     * callback lands it on a page of its own site that calls this from there,
     * or signs in with `signInExternally()`, which is exempt. The identity is
     * reloaded through the guard's identity provider from the write connection
     * and must come back as the same class and key (`identity_unknown`), so the
     * provider's scopes apply. Then the application policy must allow the
     * method, and the sign-in follows the order `signIn()` does from the
     * identity on (with no identifier type, so the verified-identifier
     * requirement does not apply), so a sign-in from outside cannot skip a
     * required factor or the choice of principal. No attempt limit or timebox
     * applies: nothing is guessed here.
     *
     * The principal to act as is given here or on the context, not both. The
     * method may not be a machine credential kind (`api_key`,
     * `client_credentials`): those authenticate requests or exchanges, never
     * sessions, and a session recorded under one would pass for a machine
     * credential to everything that reads the method. Nor may it be
     * `external_provider`: a session an external identity provider established
     * starts only through `signInExternally()`, from the result the link
     * contract maps to its identity, so it always records its provenance.
     *
     * The session's first proof names no channel and no `amr` value, timed now:
     * nothing describes how the identity was verified.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $method
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function start(Identity $identity, ?Principal $principal, string $method, ?SignInContext $context = null): SignInResult
    {
        SessionPreconditions::assertSessionMethod($method);

        $transport = $this->transport();
        $context ??= SignInContext::fromRequest($this->context->request());
        $pinned = SessionPreconditions::pinnedPrincipal($principal, $context);
        $proof  = SignInProof::unattested($method, CarbonImmutable::now());

        $outcome = SessionPreconditions::crossSite($transport, $context->client) ?? $this->startFor($identity, $pinned, $method, $context, $proof);

        return $outcome instanceof Refused ? $this->fail($outcome, $method, $context, null, []) : $this->bound($outcome, $transport);
    }

    /**
     * The live pending session of this guard the pending credential names, or
     * `null`; with an action, also `null` when the session does not allow the
     * action now (only its first outstanding requirement's actions are). Also
     * `null` when the session can no longer activate because its identity, its
     * method, or the principal and active tenant it records would be refused (a
     * machine or inactive identity, an identifier type the application no
     * longer admits, a method no longer allowed, a principal or tenant the
     * application or `TenantAccess` no longer admits, or one inactive). The
     * seam an adapter checks before each action it takes for a pending session
     * (listing or verifying factors, enrolling one), and the source of the
     * principals a choice screen lists. A read: it dispatches nothing and
     * writes nothing.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $credential
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction  $action
     * @return ?\SineMacula\Laravel\Authentication\Sessions\PendingSession
     *
     * @throws \Throwable
     */
    public function pending(#[\SensitiveParameter] Secret|string $credential, ?PendingAction $action = null): ?PendingSession
    {
        return $this->pendings->pending($credential, $action, CarbonImmutable::now()->startOfSecond());
    }

    /**
     * Satisfy the further factor the pending session waits on with the proof
     * the factor's adapter verified, and activate the session when nothing else
     * is outstanding.
     *
     * The proof must be an `additional_factor` or a `recovery_code` made for
     * `sign_in`, or an `additional_factor` made for `enrollment` (the factor
     * that confirms a bootstrap enrolment), accepted by the adapter, made no
     * later than now and no earlier than the session began waiting
     * (`proof_invalid`), and bound to the session's owner, this guard and the
     * session's id (`PendingSession::$id`; `proof_binding_mismatch`). The
     * session is checked again (the identity, the method, the principal and
     * tenant it records), the proof is stored with the session's other proofs,
     * the authentication policy of the tenant it records is asked (one
     * requiring a connection the session was not established through refuses as
     * `sso_required`, the proof unstored), and what it still waits on is judged
     * again: it activates (the guard is bound, the pair issued, the pending
     * credential consumed), stays pending, or moves on to the choice of
     * principal. A refusal leaves the session pending and the proof unstored; a
     * credential that names no live pending session of this guard fails as
     * `pending_invalid`. A cookie application's client that did not come from a
     * page of its own site fails as `cross_site_request` before the pending
     * session is read. Every refusal is reported with Laravel's `Failed` and
     * `AuthenticationFailed`.
     *
     * The client is the request's unless one is given: a service layer that
     * keeps HTTP out passes the `ClientContext` its controller built, which is
     * judged by the same-site rule (a context without its `Origin`, scheme and
     * host or custom header fails it on a cookie application), written by the
     * activation as the session's last use, and carried by the events that
     * report the action (`AuthenticationFailed`, `SessionCreated` or
     * `SessionActivated`, `SignedIn`, a superseded session's `SessionRevoked`);
     * the guard's bind describes the guard's own request, as every later event
     * of the guard does, so its `SessionAuthenticated` records that request as
     * the last use whenever `session.last_used_throttle_seconds` allows a use
     * so soon after the activation (with `0`, always).
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $credential
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofResult  $proof
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    public function satisfy(#[\SensitiveParameter] Secret|string $credential, ProofResult $proof, ?ClientContext $client = null): SignInResult
    {
        $transport = $this->transport();
        $client ??= $this->context->client();
        $outcome = SessionPreconditions::crossSite($transport, $client)
            ?? $this->pendings->satisfy($credential, $proof, CarbonImmutable::now()->startOfSecond(), $client);

        return $this->acted($outcome, $transport, $client);
    }

    /**
     * Choose the principal the pending session acts as, and the tenant it is to
     * be active in (the principal's own unless one is given), and activate the
     * session when nothing else is outstanding.
     *
     * The choice must be the session's first outstanding requirement
     * (`pending_action_not_allowed`); the principal must be the identity's,
     * resolved through the hinted path as the very one named
     * (`principal_mismatch`), and admitted by the application; the tenant must
     * be one it may act in, and active; and the identity and method are checked
     * again. Then the tenant's authentication policy is asked: one requiring
     * sign-in through a connection the session was not established through
     * refuses this principal (`sso_required`), recording nothing. Then the
     * identity-level factor policy is asked again: a further factor it now asks
     * for, or one the tenant's policy requires that the session's proofs do not
     * meet, records the principal and tenant and leaves the session waiting for
     * it; otherwise the session activates. A refusal leaves the session pending
     * for another choice; a credential that names no live pending session of
     * this guard fails as `pending_invalid`; a cookie application's client that
     * did not come from a page of its own site fails as `cross_site_request`
     * before the pending session is read. The client is the request's unless
     * one is given, as for `satisfy()`.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $credential
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\TenantSelection  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    public function choose(#[\SensitiveParameter] Secret|string $credential, Principal $principal, ?TenantSelection $tenant = null, ?ClientContext $client = null): SignInResult
    {
        $transport = $this->transport();
        $client ??= $this->context->client();
        $outcome = SessionPreconditions::crossSite($transport, $client)
            ?? $this->pendings->choose($credential, $principal, $tenant, CarbonImmutable::now()->startOfSecond(), $client);

        return $this->acted($outcome, $transport, $client);
    }

    /**
     * End the pending session the credential names without activating it, as
     * when its further factor was not verified or its choice of principal was
     * abandoned: it is revoked as `signed_out` (`SessionRevoked`), so its
     * credential cannot be tried again. The attempt-limit slots its sign-in
     * took stay counted: each factor guess costs a sign-in attempt. Returns
     * whether the credential named a live pending session of this guard, which
     * this call ended.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $credential
     * @return bool
     *
     * @throws \Throwable
     *
     * @imperative
     */
    public function discard(#[\SensitiveParameter] Secret|string $credential): bool
    {
        return $this->pendings->discard($credential, CarbonImmutable::now()->startOfSecond());
    }

    /**
     * The principals the identity may sign in as on this guard, for a choice or
     * a switch screen: the identity's `principals()`, read on the write
     * connection (for an identity that is its own principal, or has no
     * `principals()`, the resolver's default), that are active, act within an
     * active tenant (or none), and may use the application. Each one listed
     * from the identity's `principals()` that uses `ActsAsPrincipal` holds its
     * tenant, loaded with the others' on the write connection, so reading
     * `getTenant()` on it costs no query and never lazy-loads, even under
     * Eloquent strict mode; the resolver's default is returned as the resolver
     * gave it.
     *
     * With an identifier type, the application policy must also admit the
     * identity with it, as it admits a sign-in that used one: a switch screen
     * passes the type the session records
     * (`Auth::session()?->getSignInIdentifierType()`), so it lists nothing when
     * the application policy would refuse that session's identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $identifierType
     * @return list<\SineMacula\Laravel\Authentication\Contracts\Principal>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function principals(Identity $identity, ?string $identifierType = null): array
    {
        return $this->evaluation->principals($identity, $identifierType)[0];
    }

    /**
     * Run a sign-in from the application policy's method check to the session,
     * and bind the guard to a session it started.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\SignInMethod  $driver
     * @param  string  $method
     * @param  array<array-key, mixed>  $input
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @param  \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport  $transport
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function signInWith(
        SignInMethod $driver,
        string $method,
        #[\SensitiveParameter] array $input,
        SignInContext $context,
        AttemptSubject $subject,
        RefreshTokenTransport $transport,
    ): Refused|SignInResult {
        $policy = CredentialAttempt::checkMethod($this->container, $subject->guard, $method);

        if ($policy instanceof Refused) {
            return $policy;
        }

        $attempt = CredentialAttempt::begin($this->container->make(AttemptLimiter::class), $policy, $subject);

        if ($attempt instanceof Refused) {
            return $attempt;
        }

        $request = new SignInRequest($subject->guard, $this->context->provider(), $input, $context->client, $attempt->accounts->reserve(...));

        $verified = $this->context->timebox()->run(
            fn (Timebox $timebox) => $this->verify($driver, $method, $request, $attempt, $subject->identifierType, $timebox),
        );

        $outcome = $verified instanceof Refused ? $verified : $this->continueVerified($driver, $input, $context, $subject->identifierType, $attempt, $verified);

        return $outcome instanceof Refused ? $outcome : $this->bound($outcome, $transport, $attempt);
    }

    /**
     * Continue a sign-in whose method verified the input and whose identity is
     * admitted: select its principal (or find the principals it is to choose
     * from), rehash a password whose hash is outdated once that passed, then
     * take it on to its session, active or pending.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\SignInMethod  $driver
     * @param  array<array-key, mixed>  $input
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\CredentialAttempt  $attempt
     * @param  array{0: \SineMacula\Laravel\Authentication\Contracts\Identity, 1: \SineMacula\Laravel\Authentication\Proofs\SignInProof}  $verified
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function continueVerified(
        SignInMethod $driver,
        #[\SensitiveParameter] array $input,
        SignInContext $context,
        ?string $identifierType,
        CredentialAttempt $attempt,
        array $verified,
    ): Refused|SignInResult {
        [$identity, $proof] = $verified;

        $selection = $this->establishment->select($identity, $context->principal, $context);

        if ($selection instanceof Refused) {
            return $selection;
        }

        if ($driver instanceof PasswordSignIn) {
            $driver->rehash($this->context->provider(), $identity, $input);
        }

        return $this->establishment->proceed($identity, $selection, $identifierType, $context, $proof, $attempt->windows());
    }

    /**
     * Verify the request with the sign-in method and admit the identity it
     * proves, cutting the timebox short once the identity is admitted, whatever
     * comes of the sign-in after: a method that verified the input answers with
     * the identity and the proof of its first factor, timed now; one that did
     * not, and an identity the guard does not admit, with the refusal. A
     * sign-in in which an account the method checked had no attempts left is
     * refused as `account_rate_limited`, with that account's wait, for the
     * failure events (the result still says `invalid_credentials`), even when
     * the method returned an identity regardless: it must not have checked that
     * secret. A method that answers with a reason only the session service may
     * give is misconfigured, and a `LogicException` says so.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\SignInMethod  $driver
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInRequest  $request
     * @param  \SineMacula\Laravel\Authentication\Sessions\CredentialAttempt  $attempt
     * @param  ?string  $identifierType
     * @param  \Illuminate\Support\Timebox  $timebox
     * @return array{0: \SineMacula\Laravel\Authentication\Contracts\Identity, 1: \SineMacula\Laravel\Authentication\Proofs\SignInProof}|\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private function verify(SignInMethod $driver, string $method, SignInRequest $request, CredentialAttempt $attempt, ?string $identifierType, Timebox $timebox): array|Refused
    {
        $verified = $driver->authenticate($request);
        $refusal  = $attempt->accountRefusal();

        if (!$verified instanceof FirstFactor) {
            return $refusal ?? new Refused(SessionPreconditions::methodReason($driver, $verified));
        }

        $proof = SignInProof::verified($method, $verified, CarbonImmutable::now());
        $refusal ??= $this->admitIdentity($verified->identity, $identifierType);

        if ($refusal !== null) {
            return $refusal;
        }

        $timebox->returnEarly();

        return [$verified->identity, $proof];
    }

    /**
     * Reload an externally verified identity through the guard's provider,
     * check the method is allowed and the identity admitted, and take it on to
     * its session: `start()`'s identity, or the one an external result is
     * linked to.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Proofs\SignInProof  $proof
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function startFor(Identity $identity, ?Principal $principal, string $method, SignInContext $context, SignInProof $proof): Refused|SignInResult
    {
        $reloaded = $this->context->provider()->retrieveById($identity->getAuthIdentifier());

        if (!$reloaded instanceof Identity || !SessionPreconditions::isSameIdentity($reloaded, $identity)) {
            return new Refused(FailureReason::IDENTITY_UNKNOWN, $identity);
        }

        if (!$this->evaluation->allowsMethod($method)) {
            return new Refused(FailureReason::METHOD_NOT_ALLOWED, $reloaded);
        }

        $selection = $this->admitIdentity($reloaded, null) ?? $this->establishment->select($reloaded, $principal, $context);

        return $selection instanceof Refused ? $selection : $this->establishment->proceed($reloaded, $selection, null, $context, $proof);
    }

    /**
     * Refuse an identity the guard does not admit to a session, once it is
     * known to own sessions: a machine identity, an inactive one, or one the
     * application policy refuses with the identifier type the sign-in used.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $identifierType
     * @return ?\SineMacula\Laravel\Authentication\Admission\Refused
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     */
    private function admitIdentity(Identity $identity, ?string $identifierType): ?Refused
    {
        SessionPreconditions::assertHoldsSessions($identity);

        $refusal = $this->evaluation->identityRefusal($identity, $identifierType);

        return $refusal === null ? null : new Refused($refusal, $identity);
    }

    /**
     * Bind the guard to the session an action on a pending session activated
     * and answer it, or report the action's refusal and answer that, with the
     * method the session records when the refusal names it.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult  $outcome
     * @param  \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport  $transport
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \InvalidArgumentException
     */
    private function acted(Refused|SignInResult $outcome, RefreshTokenTransport $transport, ClientContext $client): SignInResult
    {
        if ($outcome instanceof SignInResult) {
            return $this->bound($outcome, $transport);
        }

        return $this->fail($outcome, $outcome->session?->getSignInMethod(), new SignInContext($client), null, []);
    }

    /**
     * Answer the result with the session's pair delivered as the application's
     * transport says (a cookie application's refresh token only in its cookie),
     * and bind the guard to the session once the writes on the session's
     * connection commit, as `DeferredBind` binds it, after what reports the
     * session (`SessionCreated`, `SignedIn`), which was scheduled first. Only
     * once the bind returned are the attempt-limit slots the sign-in took given
     * back (the attempt's, for a sign-in that started active, or the ones a
     * pending session held), whether or not it bound, so a bind listener that
     * throws leaves them counted and a rolled-back sign-in gives nothing back.
     * A result without a session binds nothing and is answered as it is. The
     * transport is built before the sign-in or the action begins, so one that
     * is misconfigured fails it before anything is written or reported.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @param  \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport  $transport
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\CredentialAttempt  $attempt
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \InvalidArgumentException
     */
    private function bound(SignInResult $result, RefreshTokenTransport $transport, ?CredentialAttempt $attempt = null): SignInResult
    {
        $session = $result->session;

        if ($session === null) {
            return $result;
        }

        $tokens = $transport->deliver($session->tokens, $session->record);

        $this->binds->run(
            $session->record,
            $session->principal,
            fn () => $this->binding->login($session->identity, $session->principal, $session->record),
            fn () => $this->giveBack($session->heldSlots, $attempt),
        );

        return SignInResult::signedIn(new SignedInSession($session->identity, $session->principal, $session->record, $tokens, $session->method));
    }

    /**
     * Give back the attempt-limit slots a bound sign-in took: the attempt's, or
     * the ones its pending session held.
     *
     * A failure is reported, not thrown: the session already stands and is
     * bound, and Laravel runs a commit's callbacks in order without catching,
     * so a throw here would stop the callbacks queued after this one (another
     * session's events, the caller's own) from running. The slots not given
     * back stay counted.
     *
     * @param  list<\SineMacula\Laravel\Authentication\RateLimiting\AttemptReservation>  $held
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\CredentialAttempt  $attempt
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function giveBack(array $held, ?CredentialAttempt $attempt): void
    {
        try {
            $attempt?->release();

            foreach ($held as $reservation) {
                $this->container->make(AttemptLimiter::class)->release($reservation);
            }
        } catch (\Throwable $exception) {
            $this->container->make(ExceptionHandler::class)->report($exception);
        }
    }

    /**
     * The application's refresh token transport, from the configuration.
     *
     * @return \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function transport(): RefreshTokenTransport
    {
        return RefreshTokenTransport::forGuard($this->context->name(), $this->container->make(ConfigRepository::class));
    }

    /**
     * Report a failed sign-in, with Laravel's `Failed` and then
     * `AuthenticationFailed` (with the challenge the method's input answered,
     * and the connection and request reference of an external result being
     * redeemed), and answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Refused  $refused
     * @param  ?string  $method
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  ?string  $identifier
     * @param  array<string, string>  $credentials
     * @param  ?string  $challengeId
     * @param  ?\SineMacula\Laravel\Authentication\External\ExternalResult  $redeemed
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     */
    private function fail(
        Refused $refused,
        ?string $method,
        SignInContext $context,
        ?string $identifier,
        #[\SensitiveParameter] array $credentials,
        ?string $challengeId = null,
        ?ExternalResult $redeemed = null,
    ): SignInResult {
        $name = $this->context->name();

        $this->context->dispatch(new Failed($name, $refused->identity, $credentials));

        $this->context->dispatch(new AuthenticationFailed(
            new EventContext(
                $name,
                $context->client,
                $refused->identity,
                $refused->principal,
                $refused->tenant,
                $refused->session,
                $method,
                connectionId: $redeemed?->connectionId,
                requestReference: $redeemed?->requestReference,
            ),
            AuthenticationFlow::SIGN_IN,
            $refused->reason,
            $identifier,
            $refused->retryAfter,
            $challengeId,
        ));

        return SignInResult::failed($refused->reason, $refused->retryAfter);
    }
}
