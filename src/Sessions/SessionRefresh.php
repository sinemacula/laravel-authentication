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
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionRefresh
{
    /** @var list<\SineMacula\Laravel\Authentication\Events\Enums\FailureReason> The reasons `extract()` refuses a token with, the only ones a caller may hand in. */
    private const array EXTRACT_REFUSALS = [
        FailureReason::REFRESH_TOKEN_CONFLICT,
        FailureReason::REFRESH_TRANSPORT_MISMATCH,
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
     * Refresh with the presented token, or return `null` when none was
     * presented.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  int|string|null  $expectedSession
     * @return ?\SineMacula\Laravel\Authentication\Sessions\RefreshResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function refresh(
        #[\SensitiveParameter] FailureReason|PresentedRefreshToken|null $presented,
        ClientContext $client,
        int|string|null $expectedSession = null,
    ): ?RefreshResult {
        $transport = $this->transport();

        if ($presented instanceof FailureReason) {
            return $this->refusePresented(self::handedIn($presented), $client);
        }

        if ($presented === null) {
            return null;
        }

        $refusal = $transport->judge($presented, $client);
        $result  = $refusal === null ? $this->exchange($presented->token, $transport, $client, $expectedSession) : $this->refusePresented($refusal, $client);

        return $result->withSource($presented->source);
    }

    /**
     * The reason `RefreshTokenTransport::extract()` answered, handed in by the
     * caller; any other reason is a caller's error.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     */
    public static function handedIn(FailureReason $reason): FailureReason
    {
        if (!in_array($reason, self::EXTRACT_REFUSALS, true)) {
            throw new \InvalidArgumentException("The transport never refuses a refresh token as `{$reason->value}`: hand in only what `extract()` answered.");
        }

        return $reason;
    }

    /**
     * Who the presented refresh credential would sign in again, without
     * rotating it, or why it would not.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Sessions\RefreshCredential|null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function credential(#[\SensitiveParameter] FailureReason|PresentedRefreshToken|null $presented, ClientContext $client): FailureReason|RefreshCredential|null
    {
        if (!$presented instanceof PresentedRefreshToken) {
            return $presented;
        }

        return $this->transport()->judge($presented, $client) ?? $this->credentialOf($presented, $client);
    }

    /**
     * Who the presented refresh token would sign in again, or the refusal.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\PresentedRefreshToken  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Sessions\RefreshCredential
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function credentialOf(#[\SensitiveParameter] PresentedRefreshToken $presented, ClientContext $client): FailureReason|RefreshCredential
    {
        $now    = CarbonImmutable::now()->startOfSecond();
        $proven = $this->proof->prove($presented->token, AuthenticationFlow::REFRESH, $now, $client);

        if ($proven instanceof AuthenticationFailed) {
            return $proven->reason;
        }

        $session  = $proven->session;
        $admitted = (new RefreshAdmission($this->context->name(), $this->context->provider(), $this->context->resolver()))->admit($session, $proven->principalHint);

        if ($admitted instanceof Refused) {
            return $admitted->reason;
        }

        return PrincipalReference::isRecordedOn($session, $admitted->principal)
            ? $this->underTenantPolicy($admitted, $session, $presented->source, $client, $now)
            : FailureReason::SESSION_PRINCIPAL_MISMATCH;
    }

    /**
     * The credential of the admitted session when it meets its tenant's
     * authentication policy, judged as a refresh judges it but writing nothing.
     *
     * @param  \SineMacula\Laravel\Authentication\Admission\Admitted  $admitted
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Sessions\RefreshCredential
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function underTenantPolicy(
        Admitted $admitted,
        EloquentSession&Model $session,
        RefreshTokenSource $source,
        ClientContext $client,
        CarbonImmutable $now,
    ): FailureReason|RefreshCredential {
        return match (TenantPolicyCheck::check($this->context->name(), $admitted, $session, $client, $now)->standing) {
            TenantPolicyStanding::SSO_REQUIRED    => FailureReason::SSO_REQUIRED,
            TenantPolicyStanding::FACTOR_REQUIRED => FailureReason::ADDITIONAL_FACTOR_REQUIRED,
            TenantPolicyStanding::MET             => new RefreshCredential($admitted->identity, $admitted->principal, $admitted->tenant, $session, $source),
        };
    }

    /**
     * Report a refresh token refused before the exchange, after `Attempting`,
     * and answer it, touching no session.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Sessions\RefreshResult
     */
    private function refusePresented(FailureReason $reason, ClientContext $client): RefreshResult
    {
        $this->context->dispatch(new Attempting($this->context->name(), [], false));

        return $this->refuse(new AuthenticationFailed(new EventContext($this->context->name(), $client), AuthenticationFlow::REFRESH, $reason));
    }

    /**
     * Exchange the refresh token and bind the guard to the refreshed session
     * once the rotation commits, or return the session to pending.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $refreshToken
     * @param  \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport  $transport
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  int|string|null  $expectedSession
     * @return \SineMacula\Laravel\Authentication\Sessions\RefreshResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function exchange(
        #[\SensitiveParameter] Secret $refreshToken,
        RefreshTokenTransport $transport,
        ClientContext $client,
        int|string|null $expectedSession,
    ): RefreshResult {
        $this->context->dispatch(new Attempting($this->context->name(), [], false));

        $outcome = $this->exchange->exchange($refreshToken, $client, $expectedSession);

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
            fn () => $this->binding->loginVerified($outcome->identity, $outcome->principal, $outcome->record, $outcome->tenant, $outcome->method, $client),
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
     * Report a refused refresh with Laravel's `Failed` and then the failure,
     * and answer it.
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
     * Dispatch `Refreshed` and then `SignedIn` once the rotation commits on the
     * session's connection.
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
