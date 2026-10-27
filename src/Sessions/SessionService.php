<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
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
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
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

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtTokenService  $tokens
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \Illuminate\Database\ConnectionResolverInterface  $connections
     * @param  \Closure(): mixed  $transactions
     */
    public function __construct(

        /** The guard whose sessions the service starts. */
        private JwtGuard $guard,

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
     * an existing device; the additional-factor policy is asked; and the
     * session starts. A success gives the attempt's slots back.
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
        $type       = $driver->identifierType();
        $identifier = $driver->identifier($input);
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
        $pinned = self::pinnedPrincipal($principal, $context);
        $context ??= SignInContext::fromRequest($this->guard->getRequest());

        $outcome = $this->startFor($identity, $pinned, $method, $context);

        return $outcome instanceof RefusedSignIn ? $this->fail($outcome, $method, $context, null, []) : $outcome;
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

        $admitted = $this->guard->callInCredentialTimebox(
            fn (Timebox $timebox): AdmittedSignIn|RefusedSignIn => $this->verify($driver, $input, $context, $subject->identifierType, $timebox),
        );

        if ($admitted instanceof AdmittedSignIn && $driver instanceof PasswordSignIn) {
            $driver->rehash($this->guard->getProvider(), $admitted->identity, $input);
        }

        $outcome = $admitted instanceof AdmittedSignIn ? $this->proceed($admitted, $method, $context) : $admitted;

        if ($outcome instanceof SignInResult) {
            $limiter->release($reservation);
        }

        return $outcome;
    }

    /**
     * Verify the input with the sign-in method and admit the identity it
     * proves, cutting the timebox short only for an admitted sign-in.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\SignInMethod  $driver
     * @param  array<array-key, mixed>  $input
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
        #[\SensitiveParameter] array $input,
        SignInContext $context,
        ?string $identifierType,
        Timebox $timebox,
    ): AdmittedSignIn|RefusedSignIn {
        $verified = $driver->authenticate(new SignInRequest($this->guard->getName(), $this->guard->getProvider(), $input, $context->client));

        $outcome = $verified instanceof Identity
            ? $this->admit($verified, $context->principal, $identifierType)
            : new RefusedSignIn($verified);

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

        if (!$reloaded instanceof Identity || !self::isSameIdentity($reloaded, $identity)) {
            return new RefusedSignIn(SignInFailureReason::IDENTITY_UNKNOWN, $identity);
        }

        if (!$this->collaborator(AudiencePolicy::class)->allowsMethod($this->guard->getName(), $method)) {
            return new RefusedSignIn(SignInFailureReason::METHOD_NOT_ALLOWED, $reloaded);
        }

        $admitted = $this->admit($reloaded, $principal, null);

        return $admitted instanceof AdmittedSignIn ? $this->proceed($admitted, $method, $context) : $admitted;
    }

    /**
     * Admit the identity as the pinned principal, verified like a principal
     * pinned on `attempt()`, or as the resolver's default.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $pinned
     * @param  ?string  $identifierType
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn|\SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function admit(Identity $identity, ?Principal $pinned, ?string $identifierType): AdmittedSignIn|RefusedSignIn
    {
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
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function proceed(AdmittedSignIn $admitted, string $method, SignInContext $context): RefusedSignIn|SignInResult
    {
        $proven = $context->refreshToken === null
            ? null
            : $this->proof->provenDevice($this->guard->getName(), $admitted, $context->refreshToken);

        return $this->establish($admitted, $proven, $method, $context, CarbonImmutable::now()->startOfSecond());
    }

    /**
     * Ask the additional-factor policy about the sign-in on the proven device
     * (or none), then start the session: continue the proven device, or create
     * one. When the proven device changed before it could be continued, the
     * sign-in is reconsidered without it, factor policy included, and a device
     * is created; it never retries the device.
     *
     * Once the session is written, the guard is bound (`Validated`, `Login`,
     * `Authenticated`, `PrincipalAssigned` and `DeviceAuthenticated` fire at
     * once), and `DeviceCreated` (for a new device) and `SignedIn` are
     * dispatched once the session is committed on the device's connection.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice)|null  $proven
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn|\SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function establish(
        AdmittedSignIn $admitted,
        (EloquentDevice&Model)|null $proven,
        string $method,
        SignInContext $context,
        CarbonImmutable $now,
    ): RefusedSignIn|SignInResult {
        $admitted = $admitted->on($proven);

        if ($this->requiresAdditionalFactor($admitted, $method, $context)) {
            return RefusedSignIn::after(SignInFailureReason::ADDITIONAL_FACTOR_REQUIRED, $admitted);
        }

        $name      = $this->guard->getName();
        $lifetimes = $this->collaborator(AudiencePolicy::class)->lifetimes($name, $admitted->principal);

        $session = $proven === null
            ? $this->writer->create($name, $admitted, $method, $context, $lifetimes, $now)
            : $this->writer->continueOn($proven, $admitted, $method, $context, $lifetimes, $now);

        if ($session === null) {
            return $this->establish($admitted, null, $method, $context, $now);
        }

        $this->guard->login($session->identity, $session->principal, $session->device);

        $this->announce($session, $admitted, $context);

        return SignInResult::signedIn($session);
    }

    /**
     * Whether the additional-factor policy asks the sign-in for a further
     * factor.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return bool
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
     * Dispatch `DeviceCreated`, for a new device, and `SignedIn` once the
     * session is committed on the device's own connection.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn  $admitted
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return void
     */
    private function announce(SignedInSession $session, AdmittedSignIn $admitted, SignInContext $context): void
    {
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
    }

    /**
     * Report a failed sign-in, with Laravel's `Failed` and then `SignInFailed`,
     * and answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn  $refused
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @param  ?string  $identifier
     * @param  array<string, string>  $credentials
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     */
    private function fail(RefusedSignIn $refused, string $method, SignInContext $context, ?string $identifier, #[\SensitiveParameter] array $credentials): SignInResult
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
     * The principal a session started for an externally verified identity is
     * pinned to: the one given as the argument or on the context, which must
     * not both name one.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \InvalidArgumentException
     */
    private static function pinnedPrincipal(?Principal $principal, ?SignInContext $context): ?Principal
    {
        if ($principal === null) {
            return $context?->principal;
        }

        if ($context?->principal !== null) {
            throw new \InvalidArgumentException('Name the principal to start a session as either as the argument or on the context, not both.');
        }

        return $principal;
    }

    /**
     * Whether the provider's answer is the very identity the caller verified:
     * the same class with the same auth identifier.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $reloaded
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return bool
     */
    private static function isSameIdentity(Identity $reloaded, Identity $identity): bool
    {
        return $reloaded::class === $identity::class && IdentifierCoercion::matches($reloaded->getAuthIdentifier(), $identity->getAuthIdentifier());
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
