<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Bus\Dispatcher;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;
use SineMacula\Laravel\Authentication\Models\OneTimeCode;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\SignInMethodManager;
use SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;

/**
 * The one-time code service of a JWT guard (`Auth::codes($guard)`): sends
 * sign-in codes for the code sign-in methods, and sends and checks codes that
 * verify an identity's identifier.
 *
 * Sending a sign-in code does no work that depends on whether an identity has
 * the identifier: the guard must allow the method, the identifier must be one
 * its type's normaliser accepts, the identifier and the IP address must have
 * code requests left (`code_request` limits, counted on every request), and no
 * code may have been issued for the identifier within the resend cooldown;
 * then a code is issued and its delivery queued, once the code is committed.
 * The result, the statements run and the time taken are the same for an
 * identifier no one has, and the queued job alone decides, later, whether
 * anyone receives the code. The code signs in through
 * `Auth::sessions($guard)->signIn($method, ...)`.
 *
 * Verifying by code is the code form of the verification helpers: a code bound
 * to the guard, the identity and its current identifier of the type, which,
 * checked with `verify()`, records the verification through
 * `IdentifierVerifier`. It never signs anyone in.
 *
 * Failures are results, reported by `AuthenticationFailed`; exceptions are kept
 * for misconfiguration and server errors. The service keeps no state between
 * calls: it reads the guard's request and dispatcher, and resolves the methods,
 * policies, limiter and engine from the container, each time.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class CodeService
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The guard whose codes the service sends and checks. */
        private JwtGuard $guard,

        /** Container the methods, policies, limiter, engine and queue are resolved from. */
        private Container $container,
    ) {}

    /**
     * Send a sign-in code for the named code sign-in method to the identifier
     * the input names under the method's identifier type (for `phone_code`,
     * `['phone' => '+447700900123']`). A method that does not sign in with
     * codes is a misconfiguration (`InvalidArgumentException`).
     *
     * @param  string  $method
     * @param  array<array-key, mixed>  $input
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Codes\CodeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public function send(string $method, #[\SensitiveParameter] array $input, ?ClientContext $client = null): CodeRequest
    {
        $driver  = $this->codeMethod($method);
        $guard   = $this->guard->getName();
        $context = new EventContext($guard, $client ?? $this->servedClient(), method: $method);
        $given   = $driver->identifier($guard, $input);

        if (!$this->collaborator(AudiencePolicy::class)->allowsMethod($guard, $method)) {
            return $this->refuse(CodeRequest::methodNotAllowed(), FailureReason::METHOD_NOT_ALLOWED, $context, $given);
        }

        $binding = $driver->binding($guard, $input);

        return $binding === null
            ? $this->refuse(CodeRequest::identifierInvalid(), FailureReason::INVALID_CREDENTIALS, $context, $given)
            : $this->issue($binding, $context, $given);
    }

    /**
     * Send a code that verifies the identity's current identifier of the type,
     * read on the write connection, to that identifier. An identity that cannot
     * verify identifiers (`LogicException`), or that is a machine identity,
     * which has none to verify (`InvalidArgumentException`), is a
     * misconfiguration; one with no identifier of the type, or one its type's
     * normaliser rejects, is `identifier_invalid`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Codes\CodeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public function sendVerification(Identity $identity, string $type, ?ClientContext $client = null): CodeRequest
    {
        $binding = $this->verificationBinding($identity, $type);
        $context = new EventContext($this->guard->getName(), $client ?? $this->servedClient(), $identity);

        return $binding === null
            ? $this->refuse(CodeRequest::identifierInvalid(), FailureReason::INVALID_CREDENTIALS, $context, null)
            : $this->issue($binding, $context, null, $identity);
    }

    /**
     * Check a verification code for the identity's current identifier of the
     * type, and record the identifier verified when it is accepted: the
     * verifier's outcome, as `IdentifierVerifier::verify()` gives it. Otherwise
     * why not (`invalid_credentials`, `code_expired` or `code_exhausted`; not
     * concealed, since the caller already holds the identity), reported by
     * `AuthenticationFailed`. A code sent before the identifier changed is
     * bound to the old one, so it verifies nothing; one whose identifier
     * changed after the identity was loaded is used up and answers `mismatch`,
     * with nothing recorded or reported, as the verifier gives it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  string  $code
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    public function verify(Identity $identity, string $type, #[\SensitiveParameter] string $code, ?ClientContext $client = null): FailureReason|IdentifierVerification
    {
        $binding = $this->verificationBinding($identity, $type);
        $context = new EventContext($this->guard->getName(), $client ?? $this->servedClient(), $identity);
        $codes   = $this->collaborator(OneTimeCodes::class);

        if ($binding === null || !$codes->isWellFormed($code)) {
            return $this->refuseVerification($context, FailureReason::INVALID_CREDENTIALS);
        }

        $failure = $codes->check($binding, $code, CarbonImmutable::now()->startOfSecond())->failure();

        return $failure === null
            ? $this->collaborator(IdentifierVerifier::class)->verify($this->guard->getName(), $identity, $type, $binding->identifier, $context->client)
            : $this->refuseVerification($context, $failure);
    }

    /**
     * Take a code request from the identifier's and the IP address's limits,
     * issue the code and queue its delivery; malformed settings, the code key
     * among them, fail closed before anything is counted. A connection that
     * could run the delivery during its dispatch gets it after the response: a
     * `sync` one runs it then, and a `failover` one that can fall back to
     * `sync` is pushed to then.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  ?string  $given
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Codes\CodeRequest
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    private function issue(CodeBinding $binding, EventContext $context, ?string $given, ?Identity $identity = null): CodeRequest
    {
        $config   = $this->collaborator(Repository::class);
        $settings = new CodeSettings($config);

        $settings->validate();
        (new CodeKeys($config))->validate();

        $synchronous = $settings->deliversSynchronously();
        $fallsBack   = $settings->fallsBackToSync();
        $reservation = $this->collaborator(AttemptLimiter::class)->acquire(
            new AttemptSubject($binding->guard, AttemptFlow::CODE_REQUEST, $binding->identifier, $binding->type, $context->client->ip),
        );

        if ($reservation->retryAfter !== null) {
            return $this->refuse(CodeRequest::rateLimited($reservation->retryAfter), FailureReason::RATE_LIMITED, $context, $given, $reservation->retryAfter);
        }

        $issued = $this->collaborator(OneTimeCodes::class)->issue($binding, CarbonImmutable::now()->startOfSecond());

        if (is_int($issued)) {
            return $this->refuse(CodeRequest::rateLimited($issued), FailureReason::RATE_LIMITED, $context, $given, $issued);
        }

        $job = (new SendOneTimeCode($binding, $issued, $identity))
            ->onConnection($settings->queueConnection())
            ->onQueue($settings->queueName())
            ->beforeCommit();

        $this->afterCommit(function () use ($job, $synchronous, $fallsBack): void {
            $bus = $this->collaborator(Dispatcher::class);

            match (true) {
                $synchronous => $bus->dispatchAfterResponse($job),
                $fallsBack   => $this->collaborator(Application::class)->terminating(static fn (): mixed => $bus->dispatch($job)),
                default      => $bus->dispatch($job),
            };
        });

        return CodeRequest::sent($issued->expiresAt);
    }

    /**
     * The verification binding of the identity's current identifier of the
     * type, read on the write connection, in its normal form; `null` when it
     * has none the type's normaliser accepts.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @return ?\SineMacula\Laravel\Authentication\Codes\CodeBinding
     *
     * @throws \InvalidArgumentException
     */
    private function verificationBinding(Identity $identity, string $type): ?CodeBinding
    {
        if ($identity instanceof MachineIdentity) {
            throw new \InvalidArgumentException(sprintf('%s is a machine identity: it has no identifiers to verify by code.', $identity::class));
        }

        $identifier = CodeIdentifiers::of(IdentifierVerifier::verifiable($identity), IdentifierType::assertValid($type), $this->collaborator(IdentifierVerifier::class));

        return $identifier === null ? null : CodeBinding::verification($this->guard->getName(), $type, $identifier, $identity);
    }

    /**
     * Report a refused code request with `AuthenticationFailed` and answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeRequest  $request
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  ?string  $given
     * @param  ?int  $retryAfter
     * @return \SineMacula\Laravel\Authentication\Codes\CodeRequest
     */
    private function refuse(CodeRequest $request, FailureReason $reason, EventContext $context, ?string $given, ?int $retryAfter = null): CodeRequest
    {
        $this->report($context, AuthenticationFlow::CODE_REQUEST, $reason, $given, $retryAfter);

        return $request;
    }

    /**
     * Report a refused verification with `AuthenticationFailed` and answer it.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    private function refuseVerification(EventContext $context, FailureReason $reason): FailureReason
    {
        $this->report($context, AuthenticationFlow::IDENTIFIER_VERIFICATION, $reason, null, null);

        return $reason;
    }

    /**
     * Dispatch `AuthenticationFailed` on the guard's current dispatcher.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow  $flow
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?string  $identifier
     * @param  ?int  $retryAfter
     * @return void
     */
    private function report(EventContext $context, AuthenticationFlow $flow, FailureReason $reason, ?string $identifier, ?int $retryAfter): void
    {
        $this->guard->getDispatcher()->dispatch(new AuthenticationFailed($context, $flow, $reason, $identifier, $retryAfter));
    }

    /**
     * The code sign-in method registered under the name.
     *
     * @param  string  $method
     * @return \SineMacula\Laravel\Authentication\Codes\CodeSignIn
     *
     * @throws \InvalidArgumentException
     */
    private function codeMethod(string $method): CodeSignIn
    {
        $driver = $this->collaborator(SignInMethodManager::class)->method($method);

        if (!$driver instanceof CodeSignIn) {
            throw new \InvalidArgumentException(sprintf('Sign-in method [%s] does not sign in with one-time codes.', $method));
        }

        return $driver;
    }

    /**
     * Run the callback once the codes' connection has committed, or at once
     * when it has no transaction open.
     *
     * @param  \Closure(): void  $callback
     * @return void
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     */
    private function afterCommit(\Closure $callback): void
    {
        $container = $this->container;

        (new AfterCommit(static fn (): mixed => $container->bound('db.transactions') ? $container->make('db.transactions') : null))->run(new OneTimeCode, $callback);
    }

    /**
     * The client of the request the guard is serving.
     *
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    private function servedClient(): ClientContext
    {
        return ClientContext::fromRequest($this->guard->getRequest());
    }

    /**
     * Resolve a collaborator from the container, so the binding in effect when
     * it is needed is the one used.
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
