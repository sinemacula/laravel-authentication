<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Routing;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Config\JwtGuards;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\RequestBody;
use SineMacula\Laravel\Authentication\Routing\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;
use SineMacula\Laravel\Authentication\Sessions\PendingSession;
use SineMacula\Laravel\Authentication\Sessions\PendingState;
use SineMacula\Laravel\Authentication\Sessions\RefreshCredential;

/**
 * The caller of a request, read from the credential its route declares
 * (`DeclaredCredential`), for the `me` route binding.
 *
 * The access credential is the guard's own: its identity, principal, active
 * tenant and session, the guard reporting its own failures. The refresh
 * credential is the one the guard's refresh token transport reads, proven and
 * admitted as a refresh would be and judged against the tenant's authentication
 * policy as a refresh judges it, without rotating or writing, though a replayed
 * one revokes its session. The pending credential is read from the configured
 * body field, never the query string or a header, and must name a live pending
 * session of the guard that allows the declared action now. A refresh or
 * pending credential the request carries and that is refused is reported once,
 * with `AuthenticationFailed` and its reason (flow `refresh`, or `sign_in` with
 * `pending_invalid` or `pending_action_not_allowed`), never the credential; a
 * request that carries none is not reported.
 *
 * The caller is read only when a binding asks for it, and at most once per
 * request for a guard and a credential: it is kept on the request's attributes
 * under that key, so a route with several bound parameters proves the
 * credential once, a guard changed later in the request is read afresh, and
 * nothing outlives the request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CallerCredentials
{
    /** @var string The prefix of the request attributes the callers are kept under. */
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

        /** Configuration the pending credential's field and the jwt guards are read from. */
        private Repository $config,

        /** Dispatcher a refused credential is reported to. */
        private Dispatcher $events,
    ) {}

    /**
     * The name of the guard the request's route reads its caller from: the
     * guard its declaration names, else the default guard (the one `auth:` set
     * for the route).
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    public function guard(Request $request): string
    {
        return DeclaredCredential::of($request)->guard ?? $this->auth->getDefaultDriver();
    }

    /**
     * The request's caller, read from the credential its route declares, or
     * `null` when the request carries no such credential or it is refused.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return ?\SineMacula\Laravel\Authentication\Routing\Caller
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function caller(Request $request): ?Caller
    {
        $declared = DeclaredCredential::of($request);
        $guard    = $declared->guard ?? $this->auth->getDefaultDriver();
        $key      = sprintf('%s.%s.%s.%s', self::MEMO, $declared->credential->value, $guard, $declared->action->value ?? '');
        $memo     = $request->attributes->get($key);

        if ($memo instanceof Caller || $memo === false) {
            return $memo ?: null;
        }

        $caller = match ($declared->credential) {
            CallerCredential::ACCESS  => $this->access($guard),
            CallerCredential::REFRESH => $this->refresh($request, $guard),
            CallerCredential::PENDING => $this->pending($request, $guard, $declared->action),
        };

        $request->attributes->set($key, $caller ?? false);

        return $caller;
    }

    /**
     * The principal the caller's identity may use the caller's application as
     * with the principal's identifier, as `principals()` would list it (with
     * the identifier type the caller's session records), or `null`, also for a
     * guard that keeps no sessions (an API key guard), which has no such list.
     *
     * @param  \SineMacula\Laravel\Authentication\Routing\Caller  $caller
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function admitted(Caller $caller, Principal $principal): ?Principal
    {
        if (!in_array($caller->guard, JwtGuards::names($this->config), true)) {
            return null;
        }

        return $this->auth->sessions($caller->guard)->principal($caller->identity, $principal->getPrincipalIdentifier(), $caller->session?->getSignInIdentifierType());
    }

    /**
     * The caller the guard authenticates the request as, or `null` for a guest.
     *
     * @param  string  $guard
     * @return ?\SineMacula\Laravel\Authentication\Routing\Caller
     *
     * @throws \LogicException
     */
    private function access(string $guard): ?Caller
    {
        $resolved = $this->auth->guard($guard);

        if (!$resolved instanceof ContextualGuard) {
            throw new \LogicException(sprintf('The me route binding reads its caller from a package guard; [%s] is not one.', $guard));
        }

        $identity = $resolved->identity();

        return $identity === null ? null : new Caller($guard, CallerCredential::ACCESS, $identity, $resolved->principal(), $resolved->tenant(), $resolved->session());
    }

    /**
     * The caller the request's refresh credential proves, or `null` when it
     * carries none or it is refused, which is reported.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $guard
     * @return ?\SineMacula\Laravel\Authentication\Routing\Caller
     *
     * @throws \Throwable
     */
    private function refresh(Request $request, string $guard): ?Caller
    {
        $credential = $this->auth->sessions($guard)->refreshCredentialFromRequest();

        if ($credential instanceof FailureReason) {
            $this->report(new EventContext($guard, ClientContext::fromRequest($request)), AuthenticationFlow::REFRESH, $credential);
        }

        return $credential instanceof RefreshCredential
            ? new Caller($guard, CallerCredential::REFRESH, $credential->identity, $credential->principal, $credential->tenant, $credential->session)
            : null;
    }

    /**
     * The caller the request's pending credential names, when its pending
     * session allows the action now, or `null` when it carries none or it is
     * refused, which is reported.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $guard
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction  $action
     * @return ?\SineMacula\Laravel\Authentication\Routing\Caller
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    private function pending(Request $request, string $guard, ?PendingAction $action): ?Caller
    {
        $body  = RequestBody::fields($request);
        $field = PendingState::credentialField($this->config);

        if (!array_key_exists($field, $body)) {
            return null;
        }

        $credential = $body[$field];
        $pending    = is_string($credential) && $credential !== '' ? $this->auth->sessions($guard)->pending($credential) : null;
        $reason     = self::pendingRefusal($pending, $action);

        if ($reason !== null || $pending === null) {
            $this->report(self::pendingContext($request, $guard, $pending), AuthenticationFlow::SIGN_IN, $reason ?? FailureReason::PENDING_INVALID);

            return null;
        }

        return new Caller($guard, CallerCredential::PENDING, $pending->identity, $pending->principal, $pending->tenant, $pending->session, $pending);
    }

    /**
     * Why the pending credential may not bind for the action, or `null` when it
     * may: `pending_invalid` when it names no live pending session of the
     * guard, `pending_action_not_allowed` when the session does not allow the
     * action now.
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
     * The context of a refused pending credential: the guard and the client,
     * with the session it names and what that session records, when it names
     * one.
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
