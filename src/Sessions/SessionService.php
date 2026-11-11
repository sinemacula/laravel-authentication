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
use SineMacula\Laravel\Authentication\Sessions\Concerns\EndsSessionsOnDeletion;
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
 * first token pair and binds the guard, or leaves the session pending.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SessionService
{
    use EndsConnectionSessions, EndsSessions, EndsSessionsOnDeletion, GatesFactorChanges, LooksUpSessions, ProvesSessions, RefreshesSessions, SignsInExternally, SwitchesSessions;

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
        $this->establishment     = new SessionEstablishment($context, $writer, $proof, $this->evaluation, $container);
        $activation              = new SessionActivation($context, $tokens, $container);
        $this->pendings          = new PendingSessions($context, $this->evaluation, $activation, $sessions, $this->afterCommit);
        $this->revocations       = new SessionRevocations($context, $sessions, $container);
        $this->policyChanges     = new TenantPolicyChanges($context, $this->afterCommit);
        $this->switchRevocations = $sessions;
        $this->transitions       = new PendingTransitions($context, $this->afterCommit, $container->make(Repository::class));

        $refreshProof = new RefreshProof($context, $tokens, $this->rotations, $this->afterCommit);
        $exchange     = new RefreshTokenExchange($tokens, $context, $connections, $transactions);

        $this->refreshes = new SessionRefresh($context, $binding, $exchange, $this->afterCommit, $this->binds, $container, $refreshProof);
        $this->signOuts  = new SessionSignOut($context, $binding, $sessions, $refreshProof, $container);

        $this->connectionRevocations = new ConnectionRevocations($context, $sessions, $this->afterCommit, $container);
        $this->factorRevocations     = new FactorRevocations($context, $this->revocations, $sessions, $this->transitions, $container);

        $issuance = new ProofIssuance($context, $tokens, $this->afterCommit);

        $this->stepUps           = new SessionStepUp($context, $issuance, $this->afterCommit);
        $this->reauthentications = new SessionReauthentication($context, $issuance, $this->afterCommit, $container);

        $this->externalReauthentications = new ExternalReauthentication($context, $issuance, $externalResults, $this->evaluation, $this->afterCommit);
        $this->factorChanges             = new FactorChangeGate($context, $container);
    }

    /**
     * Sign in with the named sign-in method and the input the client sent.
     *
     * @param  string  $method
     * @param  array<array-key, mixed>  $input
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    public function signIn(string $method, #[\SensitiveParameter] array $input, SignInContext $context): SignInResult
    {
        $began      = CarbonImmutable::now()->startOfSecond();
        $transport  = $this->transport();
        $driver     = $this->container->make(SignInMethodManager::class)->method($method);
        $type       = $driver->identifierType($this->context->name());
        $identifier = $driver->identifier($this->context->name(), $input);
        $safe       = $identifier === null ? [] : [$type ?? 'identifier' => $identifier];

        $this->context->dispatch(new Attempting($this->context->name(), $safe, false));

        $subject = new AttemptSubject($this->context->name(), AttemptFlow::SIGN_IN, $identifier, $type, $context->client->ip);
        $recheck = $this->recheck($context->client, $began);
        $outcome = SessionPreconditions::crossSite($transport, $context->client) ?? $this->signInWith($driver, $method, $input, $context, $subject, $transport, $recheck);

        if (!$outcome instanceof Refused) {
            return $outcome;
        }

        $unanswered = in_array($outcome->reason, [FailureReason::METHOD_NOT_ALLOWED, FailureReason::CROSS_SITE_REQUEST], true);

        return $this->fail($outcome, $method, $context, $identifier, $safe, $unanswered ? null : $driver->challenge($input));
    }

    /**
     * Start a session for the identity the application verified itself, from
     * the first factor it describes, through the named method.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\FirstFactor  $factor
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function start(FirstFactor $factor, ?Principal $principal, string $method, SignInContext $context): SignInResult
    {
        SessionPreconditions::assertSessionMethod($method);
        SessionPreconditions::assertApplicationFactor($factor);

        $began     = CarbonImmutable::now()->startOfSecond();
        $transport = $this->transport();
        $pinned    = SessionPreconditions::pinnedPrincipal($principal, $context);
        $proof     = SignInProof::verified($method, $factor, CarbonImmutable::now());
        $recheck   = $this->recheck($context->client, $began);

        $outcome = SessionPreconditions::crossSite($transport, $context->client) ?? $this->startFor($factor->identity, $pinned, $method, $context, $proof, $recheck);
        $outcome = $recheck->refusal()                                           ?? $outcome;

        return $outcome instanceof Refused ? $this->fail($outcome, $method, $context, null, []) : $this->bound($outcome, $transport, $recheck);
    }

    /**
     * The live pending session of this guard the pending credential names, or
     * `null` when it is gone, does not allow the action, or can no longer
     * activate.
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
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Secrets\Secret|string  $credential
     * @param  \SineMacula\Laravel\Authentication\Proofs\ProofResult  $proof
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    public function satisfy(#[\SensitiveParameter] FailureReason|Secret|string $credential, ProofResult $proof, ClientContext $client): SignInResult
    {
        $now       = CarbonImmutable::now()->startOfSecond();
        $transport = $this->transport();
        $presented = SessionPreconditions::pendingCredential($credential);
        $recheck   = $this->recheck($client, $now);
        $outcome   = SessionPreconditions::crossSite($transport, $client)
            ?? ($presented instanceof Refused ? $presented : $this->pendings->satisfy($presented, $proof, $now, $recheck));

        return $this->acted($outcome, $transport, $recheck);
    }

    /**
     * Choose the principal the pending session acts as, and the tenant it is to
     * be active in, and activate the session when nothing else is outstanding.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Secrets\Secret|string  $credential
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\TenantSelection  $tenant
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    public function choose(
        #[\SensitiveParameter] FailureReason|Secret|string $credential,
        Principal $principal,
        ClientContext $client,
        ?TenantSelection $tenant = null,
    ): SignInResult {
        $now       = CarbonImmutable::now()->startOfSecond();
        $transport = $this->transport();
        $presented = SessionPreconditions::pendingCredential($credential);
        $recheck   = $this->recheck($client, $now);
        $outcome   = SessionPreconditions::crossSite($transport, $client)
            ?? ($presented instanceof Refused ? $presented : $this->pendings->choose($presented, $principal, $tenant, $now, $recheck));

        return $this->acted($recheck->refusal() ?? $outcome, $transport, $recheck);
    }

    /**
     * End the pending session the credential names without activating it;
     * whether it named a live pending session of this guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $credential
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return bool
     *
     * @throws \Throwable
     *
     * @imperative
     */
    public function discard(#[\SensitiveParameter] Secret|string $credential, ClientContext $client): bool
    {
        return $this->pendings->discard($credential, CarbonImmutable::now()->startOfSecond(), $client);
    }

    /**
     * The principals the identity may sign in as on this guard, for a choice or
     * a switch screen.
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
     * @param  \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck  $recheck
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
        AdmissionRecheck $recheck,
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

        $outcome = $verified instanceof Refused ? $verified : $this->continueVerified($driver, $input, $context, $subject->identifierType, $attempt, $verified, $recheck);
        $outcome = $recheck->refusal() ?? $outcome;

        return $outcome instanceof Refused ? $outcome : $this->bound($outcome, $transport, $recheck, $attempt);
    }

    /**
     * Continue a sign-in whose method verified the input and whose identity is
     * admitted, on to its session, active or pending.
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
     * @param  \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck  $recheck
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
        AdmissionRecheck $recheck,
    ): Refused|SignInResult {
        [$identity, $proof] = $verified;

        $selection = $this->establishment->select($identity, $context->principal, $context);

        if ($selection instanceof Refused) {
            return $selection;
        }

        if ($driver instanceof PasswordSignIn) {
            $driver->rehash($this->context->provider(), $identity, $input);
        }

        return $this->establishment->proceed($identity, $selection, $identifierType, $context, $proof, $recheck, $attempt->windows());
    }

    /**
     * Verify the request with the sign-in method and admit the identity it
     * proves, cutting the timebox short once the identity is admitted.
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
     * check the method and identity, and take it on to its session.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\Proofs\SignInProof  $proof
     * @param  \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck  $recheck
     * @return \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function startFor(
        Identity $identity,
        ?Principal $principal,
        string $method,
        SignInContext $context,
        SignInProof $proof,
        AdmissionRecheck $recheck,
    ): Refused|SignInResult {
        $reloaded = $this->context->provider()->retrieveById($identity->getAuthIdentifier());

        if (!$reloaded instanceof Identity || !SessionPreconditions::isSameIdentity($reloaded, $identity)) {
            return new Refused(FailureReason::IDENTITY_UNKNOWN, $identity);
        }

        if (!$this->evaluation->allowsMethod($method)) {
            return new Refused(FailureReason::METHOD_NOT_ALLOWED, $reloaded);
        }

        $selection = $this->admitIdentity($reloaded, null) ?? $this->establishment->select($reloaded, $principal, $context);

        return $selection instanceof Refused ? $selection : $this->establishment->proceed($reloaded, $selection, null, $context, $proof, $recheck);
    }

    /**
     * Refuse an identity the guard does not admit to a session.
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
     * Bind the guard to the session an action on a pending session activated,
     * or report the action's refusal, and answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Refused|\SineMacula\Laravel\Authentication\Sessions\SignInResult  $outcome
     * @param  \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport  $transport
     * @param  \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck  $recheck
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \InvalidArgumentException
     */
    private function acted(Refused|SignInResult $outcome, RefreshTokenTransport $transport, AdmissionRecheck $recheck): SignInResult
    {
        if ($outcome instanceof SignInResult) {
            return $this->bound($outcome, $transport, $recheck);
        }

        return $this->fail($outcome, $outcome->session?->getSignInMethod(), new SignInContext($recheck->client), null, []);
    }

    /**
     * Answer the result with the session's pair delivered by the transport, and
     * bind the guard once the session's writes commit.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @param  \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport  $transport
     * @param  \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck  $recheck
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\CredentialAttempt  $attempt
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \InvalidArgumentException
     */
    private function bound(SignInResult $result, RefreshTokenTransport $transport, AdmissionRecheck $recheck, ?CredentialAttempt $attempt = null): SignInResult
    {
        $session = $result->session;

        if ($session === null) {
            return $result;
        }

        $tokens = $transport->deliver($session->tokens, $session->record);

        $this->binds->run(
            $session->record,
            $session->principal,
            fn () => $this->binding->login($session->identity, $session->principal, $session->record, $recheck->client),
            fn () => $recheck->then($session->record, fn () => $this->giveBack($session->heldSlots, $attempt)),
        );

        return SignInResult::signedIn(new SignedInSession($session->identity, $session->principal, $session->record, $tokens, $session->method));
    }

    /**
     * Give back the attempt-limit slots a bound sign-in took, reporting a
     * failure instead of throwing it.
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
     * The check a session the call writes is held to once committed.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \Carbon\CarbonImmutable  $began
     * @return \SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck
     */
    private function recheck(ClientContext $client, CarbonImmutable $began): AdmissionRecheck
    {
        return new AdmissionRecheck($this->context, $this->binding, $this->switchRevocations, $this->afterCommit, $client, $began);
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
     * Report a failed sign-in with Laravel's `Failed` and then
     * `AuthenticationFailed`, and answer it.
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
