<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\GuardBinding;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;

/**
 * Refreshes a session of one guard: exchanges the refresh token, reports the
 * rotation, and binds the guard to the refreshed session.
 *
 * Every refresh starts with Laravel's `Attempting`. A refused one dispatches
 * Laravel's `Failed` and then the exchange's `AuthenticationFailed`, and is
 * answered with its reason, `rate_limited` with the wait. A successful one
 * schedules `Refreshed` and `SignedIn` (a refresh) for once the rotation is
 * committed on the device's connection, and only then binds the guard as a
 * sign-in (`Validated`, `Login` and the bind events), with the tenant and the
 * sign-in method the exchange established, so a bind listener that throws
 * cannot withhold the report of a rotation already written.
 *
 * It runs on the guard's context, reading its request, dispatcher and
 * configuration when each refresh starts, and reaches the guard's bound state
 * only through the binding it is given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionRefresh
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Contracts\GuardBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange  $exchange
     * @param  \SineMacula\Laravel\Authentication\Database\AfterCommit  $afterCommit
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard whose sessions are refreshed. */
        private GuardContext $context,

        /** The guard's bound state, which a refresh binds to the refreshed session. */
        private GuardBinding $binding,

        /** The refresh-token exchange, bound to the same context. */
        private RefreshTokenExchange $exchange,

        /** Defers the rotation's report until the rotation commits. */
        private AfterCommit $afterCommit,

        /** Container the configuration the refresh token transport reads is resolved from. */
        private Container $container,
    ) {}

    /**
     * Refresh with a refresh token the caller read itself.
     *
     * @param  string  $refreshToken
     * @return \SineMacula\Laravel\Authentication\Sessions\RefreshResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function refresh(#[\SensitiveParameter] string $refreshToken): RefreshResult
    {
        $this->context->dispatch(new Attempting($this->context->name(), [], false));

        $client  = $this->context->client();
        $outcome = $this->exchange->exchange($refreshToken, $client);

        if ($outcome instanceof AuthenticationFailed) {
            return $this->refuse($outcome);
        }

        $this->report($outcome, $client);

        $this->binding->loginVerified($outcome->identity, $outcome->principal, $outcome->device, $outcome->tenant, $outcome->method);

        return RefreshResult::refreshed(new SignedInSession($outcome->identity, $outcome->principal, $outcome->device, $outcome->tokens, (string) $outcome->method, false));
    }

    /**
     * Refresh with the refresh token the request carries, read through the
     * guard's refresh token transport: `null`, dispatching nothing, when the
     * request carries none; a refusal of the transport's, after `Attempting`,
     * `Failed` and `AuthenticationFailed`, touching no device; otherwise
     * `refresh()` with the token, its result saying where it was read from.
     *
     * @return ?\SineMacula\Laravel\Authentication\Sessions\RefreshResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function refreshFromRequest(): ?RefreshResult
    {
        $presented = RefreshTokenTransport::forGuard($this->context->name(), $this->container->make(ConfigRepository::class))
            ->read($this->context->request());

        if ($presented instanceof PresentedRefreshToken) {
            return $this->refresh($presented->token)->withSource($presented->source);
        }

        if ($presented === null) {
            return null;
        }

        $this->context->dispatch(new Attempting($this->context->name(), [], false));

        return $this->refuse(new AuthenticationFailed(new EventContext($this->context->name(), $this->context->client()), AuthenticationFlow::REFRESH, $presented));
    }

    /**
     * Report a refused refresh, Laravel's `Failed` and then the failure, and
     * answer it with the failure's reason and wait.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\AuthenticationFailed  $failure
     * @return \SineMacula\Laravel\Authentication\Sessions\RefreshResult
     */
    private function refuse(AuthenticationFailed $failure): RefreshResult
    {
        $this->context->dispatch(new Failed($this->context->name(), null, []));

        $this->context->dispatch($failure);

        return RefreshResult::failed($failure->reason, $failure->retryAfter);
    }

    /**
     * Dispatch `Refreshed` and then `SignedIn` (a refresh, on the device it
     * continued) once the rotation is committed on the device's own connection:
     * at once when it has no open transaction, on its commit otherwise, and
     * never when it rolls back.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh  $refreshed
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return void
     */
    private function report(ExchangedRefresh $refreshed, ClientContext $client): void
    {
        $context = new EventContext($this->context->name(), $client, $refreshed->identity, $refreshed->principal, $refreshed->tenant, $refreshed->device, $refreshed->method);

        $this->afterCommit->run($refreshed->device, function () use ($context): void {
            $this->context->dispatch(new Refreshed($context));
            $this->context->dispatch(new SignedIn($context, false, true));
        });
    }
}
