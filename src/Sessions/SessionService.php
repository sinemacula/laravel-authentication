<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\SignInMethod;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\DeviceCreated;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Events\SignInFailed;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Guards\PinnedPrincipal;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn;
use SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn;
use SineMacula\Laravel\Authentication\Sessions\Admission\SignInAdmission;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;

/**
 * The session service of a JWT guard: signs in, creates or continues the
 * device, issues the first token pair, and binds the guard, in one call.
 *
 * `signIn()` verifies the input with a sign-in method; `start()` begins a
 * session for an identity something else verified (an external identity
 * provider, say). Either way the guard's audience policy must allow the method
 * and admit the identity as its principal, the identity, principal and tenant
 * must be active, and the additional-factor policy must not ask for a further
 * factor. A client that proves, with its refresh token, that it holds a
 * session of this guard for the same identity and principal continues on that
 * device; otherwise a device is created.
 *
 * Failures are results, not exceptions: Laravel's `Failed` and the package's
 * `SignInFailed` report them. Exceptions are kept for misconfiguration and
 * server errors. The service keeps no state between calls, and reads the
 * guard's provider, resolver, dispatcher and request, and the sign-in policies
 * bound in the container, each time it needs them.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SessionService
{
    /** @var \SineMacula\Laravel\Authentication\Sessions\SessionWriter Writes the device and issues the pair. */
    private SessionWriter $writer;

    /** @var \SineMacula\Laravel\Authentication\Sessions\DeviceProof Decides which device a client proved it holds. */
    private DeviceProof $proof;

    /** @var \SineMacula\Laravel\Authentication\Database\AfterCommit Defers the lifecycle events until the session commits. */
    private AfterCommit $afterCommit;

    /** @var \SineMacula\Laravel\Authentication\Sessions\PendingSignIns Issues and completes the sign-ins waiting for a further factor. */
    private PendingSignIns $pendings;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @param  \Closure(\Closure(\Illuminate\Support\Timebox): mixed): mixed  $timebox
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     * @param  \Closure(): mixed  $transactions
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function __construct(

        /** The guard whose sessions the service starts. */
        private JwtGuard $guard,

        /** Runs a callback inside the guard's credential timebox, so a failed sign-in takes as long as any other. */
        private \Closure $timebox,

        // The guard's token service.
        JwtTokenService $tokens,

        /** Container the sign-in methods and policies are resolved from. */
        private Container $container,

        // Resolver for the device's own connection.
        ConnectionResolverInterface $connections,

        // Returns the current transactions manager, if any, when called.
        \Closure $transactions,
    ) {
        $this->writer      = new SessionWriter($tokens, $connections);
        $this->proof       = new DeviceProof($tokens);
        $this->afterCommit = new AfterCommit($transactions);
        $this->pendings    = new PendingSignIns($container->make(Repository::class));
    }

    /**
     * Sign in with the named sign-in method and the input the client sent.
     *
     * In order: Laravel's `Attempting` (with only the identifier the input
     * names, never the input itself); the audience policy must allow the method
     * (`method_not_allowed`, nothing counted); the identifier and the client's
     * IP address must have attempts left (`rate_limited`); then, inside the
     * credential timebox, the method must verify the input and the identity,
     * principal (the context's, verified, or the resolver's default), tenant
     * and audience policy must admit it; a password is rehashed when its hash
     * is outdated; the client's refresh token, if any, is checked as proof of
     * an existing device; the additional-factor policy is asked, and when it
     * requires a further factor the result is a pending sign-in instead of a
     * session; otherwise the session starts. A success gives back the attempt's
     * slots and those the method took on the accounts it checked; a pending
     * sign-in keeps them all until it completes.
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
        $driver = $this->collaborator(SignInMethodManager::class)->method($method);
        $context ??= SignInContext::fromRequest($this->guard->getRequest());
        $type       = $driver->identifierType($this->guard->getName());
        $identifier = $driver->identifier($this->guard->getName(), $input);
        $safe       = $identifier === null ? [] : [$type ?? 'identifier' => $identifier];

        $this->dispatch(new Attempting($this->guard->getName(), $safe, false));

        $subject = new AttemptSubject($this->guard->getName(), AttemptFlow::SIGN_IN, $identifier, $type, $context->client->ip);
        $outcome = $this->signInWith($driver, $method, $input, $context, $subject);

        return $outcome instanceof RefusedSignIn ? $this->fail($outcome, $method, $context, $identifier, $safe) : $outcome;
    }

    /**
     * Start a session for an identity verified outside the guard, such as by an
     * external identity provider, through the named method.
     *
     * The identity is reloaded through the guard's identity provider from the
     * write connection and must come back as the same class and key
     * (`identity_unknown`), so the provider's scopes apply. Then the audience
     * policy must allow the method, the identity, principal and tenant must be
     * active and admitted (with no identifier type, so the verified-identifier
     * requirement does not apply), and the additional-factor policy is asked,
     * so a sign-in from outside cannot skip a required factor. No attempt limit
     * or timebox applies: nothing is guessed here.
     *
     * The principal to act as is given here or on the context, not both.
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
        $context ??= SignInContext::fromRequest($this->guard->getRequest());
        $pinned = SessionPreconditions::pinnedPrincipal($principal, $context);

        $outcome = $this->startFor($identity, $pinned, $method, $context);

        return $outcome instanceof RefusedSignIn ? $this->fail($outcome, $method, $context, null, []) : $outcome;
    }

    /**
     * Look up the pending sign-in the token completes, without using it up:
     * `null` when the token names no live pending sign-in of this guard, or its
     * identity or principal no longer resolve as recorded.
     *
     * Code that verifies a further factor calls this first, verifies the factor
     * for the identity and principal it returns, and only then calls
     * `complete()`.
     *
     * @param  string  $token
     * @return ?\SineMacula\Laravel\Authentication\Sessions\PendingFactor
     *
     * @throws \Throwable
     */
    public function pending(#[\SensitiveParameter] string $token): ?PendingFactor
    {
        $found = $this->pendings->find(
            $this->guard->getName(),
            $token,
            $this->guard->getProvider(),
            $this->guard->getPrincipalResolver(),
            CarbonImmutable::now()->startOfSecond(),
        );

        return $found?->factor;
    }

    /**
     * Complete a pending sign-in once its further factor has been verified, and
     * start its session. A trusted entry point, like `start()`: the caller must
     * have verified the factor for the pending sign-in's identity and
     * principal.
     *
     * The pending sign-in is used up whatever the outcome, by a delete that
     * only one completion can make, and gives the attempt-limit slots its
     * sign-in took back only when the session starts. In the same transaction
     * it is checked again (the method still allowed, the identity, principal
     * and tenant active, and the audience policy admitting them with the
     * identifier type the sign-in used) and the session is written, continuing
     * the proven device when it is unchanged and otherwise creating one. The
     * factor policy is not asked again. Every token that does not complete a
     * live pending sign-in of this guard fails as `pending_invalid`.
     *
     * @param  string  $token
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    public function complete(#[\SensitiveParameter] string $token): SignInResult
    {
        $now   = CarbonImmutable::now()->startOfSecond();
        $found = $this->pendings->find($this->guard->getName(), $token, $this->guard->getProvider(), $this->guard->getPrincipalResolver(), $now);

        if ($found === null) {
            return $this->fail(new RefusedSignIn(SignInFailureReason::PENDING_INVALID), null, SignInContext::fromRequest($this->guard->getRequest()), null, []);
        }

        $context = PendingSignIns::context($found->pending, ClientContext::fromRequest($this->guard->getRequest()));
        $outcome = $found->pending->getConnection()->transaction(fn (): array|RefusedSignIn => $this->completeWith($found, $context, $now));

        if ($outcome instanceof RefusedSignIn) {
            return $this->fail($outcome, $found->factor->method, $context, null, []);
        }

        [$admitted, $session] = $outcome;

        $reservation = PendingSignIns::reservation($found->pending);

        if ($reservation !== null) {
            $this->collaborator(AttemptLimiter::class)->release($reservation);
        }

        return $this->signedIn($session, $admitted, $context);
    }

    /**
     * Use up a pending sign-in without starting a session, as when its further
     * factor was not verified, so its token cannot be tried again. The
     * attempt-limit slots its sign-in took stay counted: each factor guess
     * costs a sign-in attempt. Returns whether the token named a live pending
     * sign-in of this guard, which this call used up; nothing is dispatched.
     *
     * @param  string  $token
     * @return bool
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     *
     * @imperative
     */
    public function discard(#[\SensitiveParameter] string $token): bool
    {
        return $this->pendings->discard($this->guard->getName(), $token, CarbonImmutable::now()->startOfSecond());
    }

    /**
     * Run a sign-in from the audience policy's method check to the session.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\SignInMethod  $driver
     * @param  string  $method
     * @param  array<array-key, mixed>  $input
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject  $subject
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function signInWith(
        SignInMethod $driver,
        string $method,
        #[\SensitiveParameter] array $input,
        SignInContext $context,
        AttemptSubject $subject,
    ): RefusedSignIn|SignInResult {
        if (!$this->collaborator(AudiencePolicy::class)->allowsMethod($subject->guard, $method)) {
            return new RefusedSignIn(SignInFailureReason::METHOD_NOT_ALLOWED);
        }

        $limiter     = $this->collaborator(AttemptLimiter::class);
        $reservation = $limiter->acquire($subject);

        if (!$reservation->granted()) {
            return new RefusedSignIn(SignInFailureReason::RATE_LIMITED, retryAfter: $reservation->retryAfter);
        }

        $accounts = new AccountAttempts($limiter, $subject->guard);
        $request  = new SignInRequest($subject->guard, $this->guard->getProvider(), $input, $context->client, $accounts);

        /** @var \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn|\SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn $admitted */
        $admitted = ($this->timebox)(
            fn (Timebox $timebox): AdmittedSignIn|RefusedSignIn => $this->verify($driver, $request, $accounts, $context, $subject->identifierType, $timebox),
        );

        if ($admitted instanceof AdmittedSignIn && $driver instanceof PasswordSignIn) {
            $driver->rehash($this->guard->getProvider(), $admitted->identity, $input);
        }

        $outcome = $admitted instanceof AdmittedSignIn
            ? $this->proceed($admitted, $method, $subject->identifierType, $context, [...$reservation->windows, ...$accounts->windows()])
            : $admitted;

        if ($outcome instanceof SignInResult && $outcome->isSignedIn()) {
            $limiter->release($reservation);
            $accounts->release();
        }

        return $outcome;
    }

    /**
     * Verify the request with the sign-in method and admit the identity it
     * proves, cutting the timebox short only for an admitted sign-in. A method
     * that failed after an account it checked had no attempts left is refused
     * as `account_rate_limited`, with that account's wait, for the failure
     * events; the result still says `invalid_credentials`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\SignInMethod  $driver
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInRequest  $request
     * @param  \SineMacula\Laravel\Authentication\Sessions\AccountAttempts  $accounts
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  ?string  $identifierType
     * @param  \Illuminate\Support\Timebox  $timebox
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn|\SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function verify(
        SignInMethod $driver,
        SignInRequest $request,
        AccountAttempts $accounts,
        SignInContext $context,
        ?string $identifierType,
        Timebox $timebox,
    ): AdmittedSignIn|RefusedSignIn {
        $verified = $driver->authenticate($request);

        $outcome = match (true) {
            $verified instanceof Identity    => $this->admit($verified, $context->principal, $identifierType),
            $accounts->refusedFor() !== null => new RefusedSignIn(SignInFailureReason::ACCOUNT_RATE_LIMITED, retryAfter: $accounts->refusedFor()),
            default                          => new RefusedSignIn($verified),
        };

        if ($outcome instanceof AdmittedSignIn) {
            $timebox->returnEarly();
        }

        return $outcome;
    }

    /**
     * Reload an externally verified identity through the guard's provider,
     * check the method is allowed, and admit it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function startFor(Identity $identity, ?Principal $principal, string $method, SignInContext $context): RefusedSignIn|SignInResult
    {
        $reloaded = $this->guard->getProvider()->retrieveById($identity->getAuthIdentifier());

        if (!$reloaded instanceof Identity || !SessionPreconditions::isSameIdentity($reloaded, $identity)) {
            return new RefusedSignIn(SignInFailureReason::IDENTITY_UNKNOWN, $identity);
        }

        if (!$this->collaborator(AudiencePolicy::class)->allowsMethod($this->guard->getName(), $method)) {
            return new RefusedSignIn(SignInFailureReason::METHOD_NOT_ALLOWED, $reloaded);
        }

        $admitted = $this->admit($reloaded, $principal, null);

        return $admitted instanceof AdmittedSignIn ? $this->proceed($admitted, $method, null, $context) : $admitted;
    }

    /**
     * Use the pending sign-in up, check it again, and write its session, all in
     * the caller's transaction.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\FoundPendingSignIn  $found
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \Carbon\CarbonImmutable  $now
     * @return array{0: \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn, 1: \SineMacula\Laravel\Authentication\Sessions\SignedInSession}|\SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    private function completeWith(FoundPendingSignIn $found, SignInContext $context, CarbonImmutable $now): array|RefusedSignIn
    {
        $factor = $found->factor;

        SessionPreconditions::assertHoldsDevices($factor->identity);

        $audience = $this->collaborator(AudiencePolicy::class);
        $admitted = match (true) {
            !$this->pendings->consume($found, $now)                            => new RefusedSignIn(SignInFailureReason::PENDING_INVALID),
            !$audience->allowsMethod($this->guard->getName(), $factor->method) => new RefusedSignIn(SignInFailureReason::METHOD_NOT_ALLOWED, $factor->identity, $factor->principal),
            default                                                            => (new SignInAdmission($audience))->admit(
                $this->guard->getName(),
                $factor->identity,
                static fn (): Principal => $factor->principal,
                SignInFailureReason::PRINCIPAL_UNRESOLVED,
                $found->pending->identifier_type,
            ),
        };

        if ($admitted instanceof RefusedSignIn) {
            return $admitted;
        }

        $origin  = PendingSignIns::origin($found->pending);
        $session = $this->write($admitted->on($found->device), $found->device, $factor->method, $context, $now, $origin)
            ?? $this->write($admitted, null, $factor->method, $context, $now, $origin);

        return [$admitted->on($session->device), $session];
    }

    /**
     * Admit the identity as the pinned principal, verified like a principal
     * pinned on `attempt()`, or as the resolver's default, once it is known to
     * own devices.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $pinned
     * @param  ?string  $identifierType
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn|\SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function admit(Identity $identity, ?Principal $pinned, ?string $identifierType): AdmittedSignIn|RefusedSignIn
    {
        SessionPreconditions::assertHoldsDevices($identity);

        $resolver = $this->guard->getPrincipalResolver();

        return (new SignInAdmission($this->collaborator(AudiencePolicy::class)))->admit(
            $this->guard->getName(),
            $identity,
            static fn (): ?Principal => $pinned === null ? $resolver->resolve($identity) : PinnedPrincipal::resolve($resolver, $identity, $pinned),
            $pinned === null ? SignInFailureReason::PRINCIPAL_UNRESOLVED : SignInFailureReason::PRINCIPAL_MISMATCH,
            $identifierType,
        );
    }

    /**
     * Take an admitted sign-in to its session: check the client's proof of an
     * existing device, then establish the session on it or on a new device.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  string  $method
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  ?array<string, string>  $attemptWindows
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function proceed(AdmittedSignIn $admitted, string $method, ?string $identifierType, SignInContext $context, ?array $attemptWindows = null): SignInResult
    {
        $proven = $context->refreshToken === null
            ? null
            : $this->proof->provenDevice($this->guard->getName(), $admitted, $context->refreshToken);

        return $this->establish($admitted, $proven, $method, $identifierType, $context, CarbonImmutable::now()->startOfSecond(), $attemptWindows);
    }

    /**
     * Ask the additional-factor policy about the sign-in on the proven device
     * (or none): when it requires a further factor, hand out a pending sign-in
     * that remembers the device and the attempt-limit slots the sign-in took;
     * otherwise start the session, continuing the proven device or creating
     * one. When the proven device changed before it could be continued, the
     * sign-in is reconsidered without it, factor policy included; it never
     * retries the device.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice)|null  $proven
     * @param  string  $method
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?array<string, string>  $attemptWindows
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function establish(
        AdmittedSignIn $admitted,
        (EloquentDevice&Model)|null $proven,
        string $method,
        ?string $identifierType,
        SignInContext $context,
        CarbonImmutable $now,
        ?array $attemptWindows,
    ): SignInResult {
        $admitted = $admitted->on($proven);

        if ($this->requiresAdditionalFactor($admitted, $method, $context)) {
            return SignInResult::pendingFactor($this->pendings->issue($this->guard->getName(), $admitted, $method, $identifierType, $context, $now, $attemptWindows));
        }

        $session = $this->write($admitted, $proven, $method, $context, $now);

        return $session === null
            ? $this->establish($admitted, null, $method, $identifierType, $context, $now, $attemptWindows)
            : $this->signedIn($session, $admitted, $context);
    }

    /**
     * Write the session of an admitted sign-in, with the guard's lifetimes for
     * its principal: continue the proven device, or create one, recorded as
     * created from the origin's client when that differs from the context's (a
     * completion records where its sign-in began). `null` when the proven
     * device changed before it could be continued.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice)|null  $proven
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \Carbon\CarbonImmutable  $now
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $origin
     * @return ($proven is null ? \SineMacula\Laravel\Authentication\Sessions\SignedInSession : ?\SineMacula\Laravel\Authentication\Sessions\SignedInSession)
     *
     * @throws \Throwable
     */
    private function write(
        AdmittedSignIn $admitted,
        (EloquentDevice&Model)|null $proven,
        string $method,
        SignInContext $context,
        CarbonImmutable $now,
        ?ClientContext $origin = null,
    ): ?SignedInSession {
        $name      = $this->guard->getName();
        $lifetimes = $this->collaborator(AudiencePolicy::class)->lifetimes($name, $admitted->principal);

        return $proven === null
            ? $this->writer->create($name, $admitted, $method, $context, $lifetimes, $now, $origin ?? $context->client)
            : $this->writer->continueOn($proven, $admitted, $method, $context, $lifetimes, $now);
    }

    /**
     * Whether the additional-factor policy asks the sign-in for a further
     * factor.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return bool
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function requiresAdditionalFactor(AdmittedSignIn $admitted, string $method, SignInContext $context): bool
    {
        return $this->collaborator(AdditionalFactorPolicy::class)->requiresAdditionalFactor(new AdditionalFactorContext(
            $this->guard->getName(),
            $admitted->identity,
            $admitted->principal,
            $admitted->tenant,
            $method,
            $context->client,
            $context->clientName,
            $context->platform,
            $admitted->device,
        ));
    }

    /**
     * Bind the guard to a written session, at once (`Validated`, `Login`,
     * `Authenticated`, `PrincipalAssigned` and `DeviceAuthenticated`), and
     * dispatch `DeviceCreated`, for a new device, and `SignedIn` once the
     * session is committed on the device's own connection.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     */
    private function signedIn(SignedInSession $session, AdmittedSignIn $admitted, SignInContext $context): SignInResult
    {
        $this->guard->login($session->identity, $session->principal, $session->device);

        $name    = $this->guard->getName();
        $created = $session->deviceCreated
            ? new DeviceCreated($name, $session->identity, $session->principal, $admitted->tenant, $session->device, $session->method, $context->client)
            : null;
        $signedIn = new SignedIn($name, $session->identity, $session->principal, $admitted->tenant, $session->device, $session->method, $context->client, $session->deviceCreated);

        $this->afterCommit->run($session->device, function () use ($created, $signedIn): void {

            if ($created !== null) {
                $this->dispatch($created);
            }

            $this->dispatch($signedIn);
        });

        return SignInResult::signedIn($session);
    }

    /**
     * Report a failed sign-in, with Laravel's `Failed` and then `SignInFailed`,
     * and answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn  $refused
     * @param  ?string  $method
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  ?string  $identifier
     * @param  array<string, string>  $credentials
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     */
    private function fail(RefusedSignIn $refused, ?string $method, SignInContext $context, ?string $identifier, #[\SensitiveParameter] array $credentials): SignInResult
    {
        $name = $this->guard->getName();

        $this->dispatch(new Failed($name, $refused->identity, $credentials));

        $this->dispatch(new SignInFailed(
            $name,
            $refused->identity,
            $refused->principal,
            $refused->tenant,
            $refused->device,
            $method,
            $context->client,
            $refused->reason,
            $identifier,
            $refused->retryAfter,
        ));

        return SignInResult::failed($refused->reason, $refused->retryAfter);
    }

    /**
     * Dispatch an event on the guard's current dispatcher.
     *
     * @param  object  $event
     * @return void
     */
    private function dispatch(object $event): void
    {
        $this->guard->getDispatcher()->dispatch($event);
    }

    /**
     * Resolve a sign-in collaborator from the container, so the binding in
     * effect when it is needed is the one used.
     *
     * @template TCollaborator of object
     *
     * @param  class-string<TCollaborator>  $abstract
     * @return TCollaborator
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function collaborator(string $abstract): object
    {
        return $this->container->make($abstract);
    }
}
