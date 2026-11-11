<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Callers;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\Config\JwtGuards;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\GuardBinding;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;
use SineMacula\Laravel\Authentication\Sessions\PendingCredential;
use SineMacula\Laravel\Authentication\Sessions\PendingSession;
use SineMacula\Laravel\Authentication\Sessions\RefreshCredential;

/**
 * Reads a request's caller from the credential its route declares, behind
 * `Auth::caller()`, re-reading an access caller once its guard's state changes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CallerCredentials
{
    /** @var string The request attribute the callers are kept under. */
    private const string MEMO = 'authentication.caller';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\AuthManager  $auth
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     */
    public function __construct(

        /** The package's auth manager, which resolves the guards and their session services. */
        private AuthManager $auth,

        /** Configuration the jwt guards are read from. */
        private Repository $config,

        /** Dispatcher a refused credential is reported to. */
        private Dispatcher $events,
    ) {}

    /**
     * The request's caller, read from the credential its route declares, or
     * `null` when the request carries no such credential or it is refused.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return ?\SineMacula\Laravel\Authentication\Callers\Caller
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     *
     * @phpstan-impure
     */
    public function caller(Request $request): ?Caller
    {
        $declared = DeclaredCredential::of($request);
        $guard    = $declared->guard ?? $this->auth->getDefaultDriver();
        $key      = sprintf('%s.%s.%s', $declared->credential->value, $guard, $declared->action?->value);
        $memo     = self::memo($request);
        $kept     = $memo[$key] ?? null;

        if ($kept !== null && $kept[0] === $this->version($declared->credential, $guard)) {
            return $kept[1] ?: null;
        }

        $caller = match ($declared->credential) {
            CallerCredential::ACCESS  => $this->access($guard),
            CallerCredential::REFRESH => $this->refresh($request, $guard),
            CallerCredential::PENDING => $this->pending($request, $guard, $declared->action),
        };

        // Resolving the request on first access changes the version.
        $request->attributes->set(self::MEMO, [$key => [$this->version($declared->credential, $guard), $caller ?? false]] + $memo);

        return $caller;
    }

    /**
     * Forget every caller kept on the request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */
    public static function forget(Request $request): void
    {
        $request->attributes->remove(self::MEMO);
    }

    /**
     * The callers kept on the request, each with the version it was read at.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array<string, array{0: ?int, 1: false|\SineMacula\Laravel\Authentication\Callers\Caller}>
     */
    private static function memo(Request $request): array
    {
        /** @var array<string, array{0: ?int, 1: false|\SineMacula\Laravel\Authentication\Callers\Caller}> */
        return $request->attributes->get(self::MEMO, []);
    }

    /**
     * The guard's bound state version for an access caller, `null` for others.
     *
     * @param  \SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential  $credential
     * @param  string  $guard
     * @return ?int
     */
    private function version(CallerCredential $credential, string $guard): ?int
    {
        if ($credential !== CallerCredential::ACCESS) {
            return null;
        }

        $resolved = $this->auth->guard($guard);

        return $resolved instanceof GuardBinding ? $resolved->boundStateVersion() : null;
    }

    /**
     * The caller the guard authenticates the request as, with the scopes its
     * credential grants, or `null` for a guest.
     *
     * @param  string  $guard
     * @return ?\SineMacula\Laravel\Authentication\Callers\Caller
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function access(string $guard): ?Caller
    {
        $resolved = $this->auth->guard($guard);

        if (!$resolved instanceof ContextualGuard) {
            throw new \LogicException(sprintf('The caller of a request is read from a package guard; [%s] is not one.', $guard));
        }

        $identity = $resolved->identity();

        if ($identity === null) {
            return null;
        }

        $sessions = in_array($guard, JwtGuards::names($this->config), true) ? $this->auth->sessions($guard) : null;

        return new Caller(
            $guard,
            CallerCredential::ACCESS,
            $identity,
            $resolved->principal(),
            $resolved->tenant(),
            $resolved->session(),
            scopes: $resolved->scopes(),
            sessions: $sessions,
        );
    }

    /**
     * The caller the request's refresh credential proves, or `null` when it
     * carries none or it is refused, which is reported.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $guard
     * @return ?\SineMacula\Laravel\Authentication\Callers\Caller
     *
     * @throws \Throwable
     */
    private function refresh(Request $request, string $guard): ?Caller
    {
        $presented = $this->auth->refreshTransport($guard)->extract($request);

        if ($presented === null) {
            return null;
        }

        $client     = ClientContext::fromRequest($request);
        $sessions   = $this->auth->sessions($guard);
        $credential = $sessions->refreshCredential($presented, $client);

        if ($credential instanceof FailureReason) {
            $this->report(new EventContext($guard, $client), AuthenticationFlow::REFRESH, $credential);
        }

        return $credential instanceof RefreshCredential
            ? new Caller($guard, CallerCredential::REFRESH, $credential->identity, $credential->principal, $credential->tenant, $credential->session, sessions: $sessions)
            : null;
    }

    /**
     * The caller the request's pending credential names, or `null` when it
     * carries none or it is refused, which is reported.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $guard
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction  $action
     * @return ?\SineMacula\Laravel\Authentication\Callers\Caller
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    private function pending(Request $request, string $guard, ?PendingAction $action): ?Caller
    {
        $credential = PendingCredential::extract($request);

        if ($credential === null) {
            return null;
        }

        $sessions = $this->auth->sessions($guard);
        $pending  = $credential instanceof Secret ? $sessions->pending($credential) : null;
        $reason   = self::pendingRefusal($pending, $action);

        if ($reason !== null || $pending === null) {
            $this->report(self::pendingContext($request, $guard, $pending), AuthenticationFlow::SIGN_IN, $reason ?? FailureReason::PENDING_INVALID);

            return null;
        }

        return new Caller($guard, CallerCredential::PENDING, $pending->identity, $pending->principal, $pending->tenant, $pending->session, $pending);
    }

    /**
     * Why the pending credential may not be read for the action, or `null` when
     * it may.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\PendingSession  $pending
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction  $action
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    private static function pendingRefusal(?PendingSession $pending, ?PendingAction $action): ?FailureReason
    {
        if ($pending === null) {
            return FailureReason::PENDING_INVALID;
        }

        return in_array($action, $pending->actions(), true) ? null : FailureReason::PENDING_ACTION_NOT_ALLOWED;
    }

    /**
     * The context of a refused pending credential, with the session it names,
     * if any.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $guard
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\PendingSession  $pending
     * @return \SineMacula\Laravel\Authentication\Events\EventContext
     */
    private static function pendingContext(Request $request, string $guard, ?PendingSession $pending): EventContext
    {
        return new EventContext($guard, ClientContext::fromRequest($request), $pending?->identity, $pending?->principal, $pending?->tenant, $pending?->session, $pending?->method);
    }

    /**
     * Report a refused credential, without the credential.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow  $flow
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     */
    private function report(EventContext $context, AuthenticationFlow $flow, FailureReason $reason): void
    {
        $this->events->dispatch(new AuthenticationFailed($context, $flow, $reason));
    }
}
