<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\GuardBinding;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh;
use SineMacula\Laravel\Authentication\Jwt\RefreshAdmission;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;
use SineMacula\Laravel\Authentication\Tenancy\Enums\TenantPolicyStanding;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyCheck;

/**
 * Refreshes a session of one guard: exchanges the refresh token, reports the
 * rotation, and binds the guard to the refreshed session.
 *
 * Every refresh starts with Laravel's `Attempting`. A refused one dispatches
 * Laravel's `Failed` and then the exchange's `AuthenticationFailed`, and is
 * answered with its reason, `rate_limited` with the wait. A successful one
 * schedules `Refreshed` and `SignedIn` (a refresh) for once the rotation is
 * committed on the session's connection, and only then binds the guard as a
 * sign-in (`Validated`, `Login` and the bind events), with the tenant and the
 * sign-in method the exchange established, once the rotation commits too, as
 * `DeferredBind` binds it: a bind listener that throws cannot withhold the
 * report of a rotation already written, and a refresh inside a transaction that
 * rolls back binds nothing.
 *
 * It runs on the guard's context, reading its request, dispatcher and
 * configuration when each refresh starts, and reaches the guard's bound state
 * only through the binding it is given. A refresh from plain values
 * (`refreshPresented()`) reads the guard's request for nothing it judges or
 * reports itself: the token, its source and the client are the caller's, judged
 * again by the transport. The guard's bind still describes the guard's own
 * request, as every later event of the guard does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionRefresh
{
    /** @var string Why a cookie application's refresh token is not handed in by the caller. */
    public const string COOKIE_ONLY = 'This application\'s refresh token travels in its cookie, whose cross-site checks a bare token cannot carry:'
        . ' refresh, switch or sign out with the *FromRequest() methods, or refresh and sign out with refreshPresented()'
        . ' and signOutPresented() from what extract() read and the request\'s client.';

    /** @var list<\SineMacula\Laravel\Authentication\Events\Enums\FailureReason> The reasons the transport refuses a request's refresh token with, the only ones a caller may hand in. */
    private const array READ_REFUSALS = [
        FailureReason::REFRESH_TOKEN_CONFLICT,
        FailureReason::REFRESH_TRANSPORT_MISMATCH,
        FailureReason::CROSS_SITE_REQUEST,
        FailureReason::TOKEN_INVALID,
    ];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Contracts\GuardBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange  $exchange
     * @param  \SineMacula\Laravel\Authentication\Database\AfterCommit  $afterCommit
     * @param  \SineMacula\Laravel\Authentication\Sessions\DeferredBind  $binds
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Authentication\Sessions\RefreshProof  $proof
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

        /** Binds the guard to the refreshed session once the rotation commits. */
        private DeferredBind $binds,

        /** Container the configuration the refresh token transport reads is resolved from. */
        private Container $container,

        /** Proves the session a refresh credential holds, without rotating it. */
        private RefreshProof $proof,
    ) {}

    /**
     * Refresh with a refresh token the caller read itself, for a body
     * application only: a cookie application's token comes from its cookie,
     * with the cookie's cross-site checks, through `refreshFromRequest()` or
     * `refreshPresented()` alone, so a token handed in here is a
     * misconfiguration (`LogicException`).
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $refreshToken
     * @return \SineMacula\Laravel\Authentication\Sessions\RefreshResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function refresh(#[\SensitiveParameter] Secret|string $refreshToken): RefreshResult
    {
        $transport = $this->transport();

        self::refuseHandedIn($transport);

        return $this->exchange($refreshToken, $transport, null);
    }

    /**
     * Refuse a bare refresh token handed in to `refresh()`, `switchTo()` or
     * `signOutWith()` when the application's token travels in its cookie, whose
     * cross-site checks only the `*FromRequest()` methods make, or
     * `refreshPresented()` and `signOutPresented()` on the token's source and
     * the request's client.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport  $transport
     * @return void
     *
     * @throws \LogicException
     */
    public static function refuseHandedIn(RefreshTokenTransport $transport): void
    {
        if ($transport->usesCookie()) {
            throw new \LogicException(self::COOKIE_ONLY);
        }
    }

    /**
     * Refuse, as a caller's error (`InvalidArgumentException`), a reason handed
     * in that is not one the transport answers (`READ_REFUSALS`).
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null  $presented
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertHandedIn(#[\SensitiveParameter] FailureReason|PresentedRefreshToken|null $presented): void
    {
        if ($presented instanceof FailureReason && !in_array($presented, self::READ_REFUSALS, true)) {
            throw new \InvalidArgumentException("The transport never refuses a refresh token as `{$presented->value}`: hand in only what `extract()` or `read()` answered.");
        }
    }

    /**
     * Refresh with the refresh token the request carries, read through the
     * application's refresh token transport: `null`, dispatching nothing, when
     * the request carries none; a refusal of the transport's, after
     * `Attempting`, `Failed` and `AuthenticationFailed`, touching no session;
     * otherwise the exchange of the token, its result saying where it was read
     * from.
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
        $transport = $this->transport();

        return $this->answer($transport->read($this->context->request()), $transport, null);
    }

    /**
     * Refresh with what the caller's code extracted from a request, judged
     * again with the client and answered as `refreshFromRequest()` answers what
     * it reads, with the client in place of the request's. A reason handed in
     * is checked before anything is dispatched.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return ?\SineMacula\Laravel\Authentication\Sessions\RefreshResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function refreshPresented(#[\SensitiveParameter] FailureReason|PresentedRefreshToken|null $presented, ClientContext $client): ?RefreshResult
    {
        $transport = $this->transport();

        self::assertHandedIn($presented);

        if ($presented instanceof PresentedRefreshToken) {

            $refusal = $transport->judge($presented, $client);

            if ($refusal !== null) {
                return $this->refusePresented($refusal, $client)->withSource($presented->source);
            }
        }

        return $this->answer($presented, $transport, $client);
    }

    /**
     * Who the refresh credential the request carries would sign in again,
     * without rotating it: `null` when the request carries none; the
     * transport's refusal; the refusal of the proof (a replay revoking the
     * session); then the session's owner admitted as a refresh admits it (the
     * owner, reloaded through the guard's provider and active, as the principal
     * the token names, which must be the one the session records, in the
     * session's active tenant, still admitted by the application policy and
     * `ApplicationAccess`); then the session judged against its tenant's
     * authentication policy, as a refresh judges it: `sso_required` for one the
     * next refresh would revoke, `additional_factor_required` for one it would
     * return to pending, neither written here. Dispatches nothing but a
     * replay's `SessionRevoked`, and binds nothing; the caller reports a
     * refusal.
     *
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Sessions\RefreshCredential|null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function credentialFromRequest(): FailureReason|RefreshCredential|null
    {
        $presented = $this->transport()->read($this->context->request());

        return $presented instanceof PresentedRefreshToken ? $this->credentialOf($presented) : $presented;
    }

    /**
     * Who the refresh token the request carried would sign in again: the
     * proof's refusal, the admission's, the tenant policy's, or the credential.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\PresentedRefreshToken  $presented
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Sessions\RefreshCredential
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function credentialOf(PresentedRefreshToken $presented): FailureReason|RefreshCredential
    {
        $now    = CarbonImmutable::now()->startOfSecond();
        $proven = $this->proof->prove($presented->token, AuthenticationFlow::REFRESH, $now);

        if ($proven instanceof AuthenticationFailed) {
            return $proven->reason;
        }

        $session  = $proven->session;
        $admitted = (new RefreshAdmission($this->context->name(), $this->context->provider(), $this->context->resolver()))->admit($session, $proven->principalHint);

        if ($admitted instanceof Refused) {
            return $admitted->reason;
        }

        return PrincipalReference::isRecordedOn($session, $admitted->principal)
            ? $this->underTenantPolicy($admitted, $session, $presented->source, $now)
            : FailureReason::SESSION_PRINCIPAL_MISMATCH;
    }

    /**
     * The credential of the admitted session when it meets its tenant's
     * authentication policy, judged as a refresh judges it but writing nothing:
     * `sso_required` for a session the next refresh would revoke,
     * `additional_factor_required` for one it would return to pending.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Sessions\RefreshCredential
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function underTenantPolicy(Admitted $admitted, EloquentSession&Model $session, RefreshTokenSource $source, CarbonImmutable $now): FailureReason|RefreshCredential
    {
        return match (TenantPolicyCheck::check($this->context->name(), $admitted->identity, $admitted->principal, $admitted->tenant, $session, $now)->standing) {
            TenantPolicyStanding::SSO_REQUIRED    => FailureReason::SSO_REQUIRED,
            TenantPolicyStanding::FACTOR_REQUIRED => FailureReason::ADDITIONAL_FACTOR_REQUIRED,
            TenantPolicyStanding::MET             => new RefreshCredential($admitted->identity, $admitted->principal, $admitted->tenant, $session, $source),
        };
    }

    /**
     * Answer what the transport read: `null` for no token, the transport's
     * refusal, reported, or the exchange of the token, its result saying where
     * it was presented. The client is the one the caller gave, or, when it gave
     * none, the guard's request's.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport  $transport
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return ?\SineMacula\Laravel\Authentication\Sessions\RefreshResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function answer(#[\SensitiveParameter] FailureReason|PresentedRefreshToken|null $presented, RefreshTokenTransport $transport, ?ClientContext $client): ?RefreshResult
    {
        if ($presented instanceof PresentedRefreshToken) {
            return $this->exchange($presented->token, $transport, $client)->withSource($presented->source);
        }

        return $presented === null ? null : $this->refusePresented($presented, $client);
    }

    /**
     * Report a refresh token refused before the exchange, after `Attempting`,
     * and answer it, touching no session.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\RefreshResult
     */
    private function refusePresented(FailureReason $reason, ?ClientContext $client): RefreshResult
    {
        $this->context->dispatch(new Attempting($this->context->name(), [], false));

        return $this->refuse(new AuthenticationFailed(new EventContext($this->context->name(), $client ?? $this->context->client()), AuthenticationFlow::REFRESH, $reason));
    }

    /**
     * Exchange the refresh token and bind the guard to the refreshed session
     * once the rotation commits, its pair delivered by the application's
     * transport at once. A session that no longer meets its tenant's
     * authentication policy for want of a further factor returns to pending:
     * the result is pending, with the pending credential instead of a pair,
     * nothing is bound, and a binding to that session is forgotten.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $refreshToken
     * @param  \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport  $transport
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\RefreshResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function exchange(#[\SensitiveParameter] Secret|string $refreshToken, RefreshTokenTransport $transport, ?ClientContext $client): RefreshResult
    {
        $this->context->dispatch(new Attempting($this->context->name(), [], false));

        $client ??= $this->context->client();
        $outcome = $this->exchange->exchange($refreshToken, $client);

        if ($outcome instanceof AuthenticationFailed) {
            return $this->refuse($outcome);
        }

        if ($outcome instanceof ReturnedToPending) {

            $this->binding->forgetSession($outcome->pending->session);

            return RefreshResult::pending($outcome->pending, $outcome->credential);
        }

        $this->report($outcome, $client);

        $tokens = $transport->deliver($outcome->tokens, $outcome->record);

        $this->binds->run(
            $outcome->record,
            $outcome->principal,
            fn () => $this->binding->loginVerified($outcome->identity, $outcome->principal, $outcome->record, $outcome->tenant, $outcome->method),
        );

        return RefreshResult::refreshed(new SignedInSession($outcome->identity, $outcome->principal, $outcome->record, $tokens, (string) $outcome->method));
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
     * Dispatch `Refreshed` and then `SignedIn` (a refresh, on the session it
     * continued) once the rotation is committed on the session's own
     * connection: at once when it has no open transaction, on its commit
     * otherwise, and never when it rolls back.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh  $refreshed
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return void
     */
    private function report(ExchangedRefresh $refreshed, ClientContext $client): void
    {
        $context = new EventContext($this->context->name(), $client, $refreshed->identity, $refreshed->principal, $refreshed->tenant, $refreshed->record, $refreshed->method);

        $this->afterCommit->run($refreshed->record, function () use ($context): void {
            $this->context->dispatch(new Refreshed($context));
            $this->context->dispatch(new SignedIn($context, true));
        });
    }
}
