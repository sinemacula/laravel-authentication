<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Logout;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\GuardBinding;
use SineMacula\Laravel\Authentication\Contracts\HasChangeableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalizers;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\IdentitySessions;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Ends sessions for one guard: signs the request's session out, revokes one
 * session or every session of an identity or a principal, and answers security
 * changes with their own reasons.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SessionRevocations
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Sessions\RevocationWriter  $revocations
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard whose sessions are ended. */
        private GuardContext $context,

        /** Revokes one session or every session of a scope, and reports it once committed. */
        private RevocationWriter $revocations,

        /** Container the identifier normalisers are resolved from. */
        private Container $container,
    ) {}

    /**
     * The revocations of the guard the context belongs to.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return self
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public static function forContext(GuardContext $context, Container $container): self
    {
        $transactions = static fn (): mixed => $container->bound('db.transactions') ? $container->make('db.transactions') : null;

        return new self($context, new RevocationWriter($container->make(ConnectionResolverInterface::class), $transactions), $container);
    }

    /**
     * Sign the request's session out, dispatch Laravel's `Logout` and forget
     * the binding; whether this call revoked a session.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\GuardBinding  $binding
     * @return bool
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     *
     * @imperative
     */
    public function signOut(GuardBinding $binding): bool
    {
        $identity = $binding->user();
        $session  = $binding->session();
        $revoked  = false;

        if ($session instanceof EloquentSession && $session instanceof Model) {

            $event = new SessionRevoked(
                new EventContext(
                    $session->getGuard(),
                    $this->context->client(),
                    $identity,
                    $binding->principal(),
                    self::boundTenant($binding),
                    $session,
                    $session->getSignInMethod(),
                    fromSession: true,
                ),
                RevocationReason::SIGNED_OUT,
            );

            $revoked = $this->revocations->revoke($session, RevocationReason::SIGNED_OUT, CarbonImmutable::now()->startOfSecond(), fn () => $this->context->dispatch($event));
        }

        if ($identity !== null) {
            $this->context->dispatch(new Logout($this->context->name(), $identity));
        }

        $binding->forgetUser();

        return $revoked;
    }

    /**
     * End every session of the binding's identity, of every guard, keeping the
     * binding's own session when asked; how many this call revoked.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\GuardBinding  $binding
     * @param  bool  $keepCurrentSession
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Throwable
     */
    public function signOutEverywhere(GuardBinding $binding, bool $keepCurrentSession): int
    {
        $identity = $binding->user();

        if ($identity === null) {
            return 0;
        }

        $session = $keepCurrentSession ? $binding->session() : null;
        $scope   = $this->identityScope($identity);

        return $this->endSessions([$keepCurrentSession && $session === null ? $scope->keepingCutoff() : $scope], RevocationReason::SIGNED_OUT_EVERYWHERE, $session);
    }

    /**
     * Revoke one session of the owner, found through its `sessions()` relation;
     * whether this call revoked it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $owner
     * @param  mixed  $sessionId
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @return bool
     *
     * @throws \LogicException
     *
     * @imperative
     */
    public function revokeSession(Identity $owner, mixed $sessionId, RevocationReason $reason): bool
    {
        $session = IdentitySessions::find($owner, $sessionId);

        if ($session === null) {
            return false;
        }

        $context = new EventContext($session->getGuard(), $this->context->client(), $owner, session: $session, method: $session->getSignInMethod(), fromSession: true);
        $event   = new SessionRevoked($context, $reason);

        return $this->revocations->revoke($session, $reason, CarbonImmutable::now()->startOfSecond(), fn () => $this->context->dispatch($event));
    }

    /**
     * Revoke every session of the identity, of every guard, except the given
     * one, and cancel its pending identifier changes; how many this call
     * revoked.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $except
     * @param  ?\Closure(): void  $committed
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function revokeSessions(Identity $identity, RevocationReason $reason, ?Session $except = null, ?\Closure $committed = null, ?ClientContext $client = null): int
    {
        return $this->endSessions([$this->identityScope($identity)], $reason, $except, $committed, client: $client);
    }

    /**
     * Revoke every session that acts as the principal, except the given one;
     * how many this call revoked.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $except
     * @return int
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function revokePrincipalSessions(Principal $principal, RevocationReason $reason, ?Session $except = null): int
    {
        return $this->endSessions([RevocationScope::principal($principal)], $reason, $except);
    }

    /**
     * The identity's password was changed: end its sessions
     * (`password_changed`), except the given session.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $except
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function passwordChanged(Identity $identity, ?Session $except = null): int
    {
        return $this->revokeSessions($identity, RevocationReason::PASSWORD_CHANGED, $except);
    }

    /**
     * The identity's password was reset: end every session it has
     * (`password_reset`).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function passwordReset(Identity $identity): int
    {
        return $this->revokeSessions($identity, RevocationReason::PASSWORD_RESET);
    }

    /**
     * A first-factor credential of the identity was removed: end its sessions
     * (`factor_removed`), except the given session.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $except
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function credentialRemoved(Identity $identity, ?Session $except = null): int
    {
        return $this->revokeSessions($identity, RevocationReason::FACTOR_REMOVED, $except);
    }

    /**
     * The identity was deactivated: end every session it has
     * (`identity_deactivated`).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function identityDeactivated(Identity $identity): int
    {
        return $this->endSessions([$this->identityScope($identity)], RevocationReason::IDENTITY_DEACTIVATED, null, changed: $identity);
    }

    /**
     * The principal was deactivated: end every session acting as it
     * (`principal_deactivated`).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return int
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function principalDeactivated(Principal $principal): int
    {
        return $this->endSessions([RevocationScope::principal($principal)], RevocationReason::PRINCIPAL_DEACTIVATED, null, changed: $principal);
    }

    /**
     * The identity was deleted, or soft-deleted: end every session it has
     * (`identity_deleted`).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function identityDeleted(Identity $identity): int
    {
        return $this->endSessions([$this->identityScope($identity)], RevocationReason::IDENTITY_DELETED, null, changed: $identity);
    }

    /**
     * The principal was deleted, or soft-deleted: end every session acting as
     * it (`principal_deleted`).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return int
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function principalDeleted(Principal $principal): int
    {
        return $this->endSessions([RevocationScope::principal($principal)], RevocationReason::PRINCIPAL_DELETED, null, changed: $principal);
    }

    /**
     * The tenant was deactivated: end every session acting as one of its
     * principals listed, or in it, as `tenant_deactivated`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  iterable<\SineMacula\Laravel\Authentication\Contracts\Principal>  $principals
     * @return int
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function tenantDeactivated(Tenant $tenant, iterable $principals): int
    {
        $scopes = [];
        $listed = [];

        foreach ($principals as $principal) {

            self::assertActsWithin($principal, $tenant);

            $recorded = [PrincipalReference::type($principal), PrincipalReference::id($principal)];

            if (in_array($recorded, $listed, true)) {
                continue;
            }

            $listed[] = $recorded;
            $scopes[] = RevocationScope::principal($principal, $tenant);
        }

        return $this->endSessions([...$scopes, RevocationScope::activeTenant($tenant)], RevocationReason::TENANT_DEACTIVATED, null, changed: $tenant);
    }

    /**
     * Every session of the identity, with its pending identifier changes when
     * its identifiers can be changed.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Sessions\RevocationScope
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function identityScope(Identity $identity): RevocationScope
    {
        $types = $identity instanceof HasChangeableIdentifiers ? $this->container->make(IdentifierNormalizers::class)->types() : [];

        return RevocationScope::identity($identity, $types);
    }

    /**
     * End every session of the scopes and report each revoked session and scope
     * once the revocations commit.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  non-empty-list<\SineMacula\Laravel\Authentication\Sessions\RevocationScope>  $scopes
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $except
     * @param  ?\Closure(): void  $committed
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity|\SineMacula\Laravel\Authentication\Contracts\Principal|\SineMacula\Laravel\Authentication\Contracts\Tenant|null  $changed
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return int
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    private function endSessions(
        array $scopes,
        RevocationReason $reason,
        ?Session $except,
        ?\Closure $committed = null,
        Identity|Principal|Tenant|null $changed = null,
        ?ClientContext $client = null,
    ): int {
        $client ??= $this->context->client();
        $guard  = $this->context->name();
        $report = function (EloquentSession&Model $session, RevocationScope $scope) use ($client, $reason): void {
            $method  = $session->getSignInMethod();
            $context = new EventContext($session->getGuard(), $client, $scope->identity, $scope->principal, $scope->tenant, $session, $method, fromSession: true);

            $this->context->dispatch(new SessionRevoked($context, $reason));
        };

        $ended = $this->revocations->revokeScopes(
            $scopes,
            $reason,
            $except,
            CarbonImmutable::now()->startOfSecond(),
            $report,
            function (RevocationScope $scope, int $revoked, ?CarbonImmutable $cutoff) use ($client, $guard, $reason, $except): void {
                if ($scope->identity === null && $scope->principal === null) {
                    return;
                }

                $context = new EventContext($guard, $client, $scope->identity, $scope->principal, $scope->tenant, $except);

                $this->context->dispatch(new SignedOutEverywhere($context, $reason, $revoked, $cutoff));
            },
            $committed,
        );

        if ($changed !== null) {
            $this->revocations->revokeAgain($scopes, $reason, $changed, $report);
        }

        return $ended;
    }

    /**
     * The binding's active tenant, or `null` when there is none or it cannot be
     * loaded.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\GuardBinding  $binding
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private static function boundTenant(GuardBinding $binding): ?Tenant
    {
        try {
            return $binding->tenant();
        } catch (TenantUnavailableException) {
            return null;
        }
    }

    /**
     * Refuse a principal that does not act within the tenant, read through
     * `WriteConnection::stored()`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertActsWithin(Principal $principal, Tenant $tenant): void
    {
        try {
            $actual = WriteConnection::stored($principal, static fn (Principal $stored): ?Tenant => $stored->getTenant());
        } catch (TenantUnavailableException $exception) {
            $actual = $exception->isFor($tenant) ? $tenant : null;
        }

        if ($actual !== null && $actual::class === $tenant::class && IdentifierCoercion::matches($actual->getTenantIdentifier(), $tenant->getTenantIdentifier())) {
            return;
        }

        $message = sprintf(
            'Principal %s %s does not act within tenant %s %s.',
            PrincipalReference::type($principal),
            PrincipalReference::id($principal),
            $tenant::class,
            IdentifierCoercion::stringify($tenant->getTenantIdentifier()),
        );

        throw new \InvalidArgumentException($message);
    }
}
