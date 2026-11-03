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
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalizers;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\SessionRecords\IdentitySessions;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Ends sessions for one guard: signs the request's session out, revokes one
 * session or every session of an identity or a principal, and answers the
 * security changes an application makes in its own flows, each ending the
 * affected sessions with its own reason.
 *
 * Every revocation marks the session (`revoked_at`, `revoked_reason`) with one
 * conditional update that only applies while it is not revoked yet: idempotent,
 * the first revocation's time and reason kept, and only the call that changed
 * the row reporting `SessionRevoked`, once the revocation is committed on the
 * session's own connection. A bulk revocation moves the scope's "tokens valid
 * after" cutoff when it records one, ends its pending sessions with the rest
 * and, for an identity, cancels its pending identifier changes; it reports each
 * session it revoked and then `SignedOutEverywhere`, also when it revoked none.
 * Deactivation already stops every token at once through the live activity
 * checks; revoking makes the end outlast a reactivation and records why.
 *
 * It runs on the guard's context: its events carry the client of the request
 * each call starts in, and go to the context's dispatcher as it is when they
 * are dispatched, a deferred report's when the revocation commits. Only the two
 * sign-out calls touch the guard's bound state, through the binding they are
 * given, so the guard's own `logout()` and the password writer use it without a
 * session service, and the session service delegates to it.
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
     * The revocations of the guard the context belongs to, on the container's
     * database connections and transactions manager.
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
     * Sign the request's session out: revoke the session the binding is bound
     * to (`signed_out`), dispatch Laravel's `Logout` when an identity was
     * bound, and forget the binding for the rest of the request. Returns
     * whether this call revoked a session.
     *
     * An access-only token, which names no stored session, has nothing to
     * revoke and is only forgotten; a guest request does nothing.
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
     * End every session of the binding's identity, of every guard, with reason
     * `signed_out_everywhere`, keeping the binding's own session when asked.
     * Returns how many sessions this call revoked; `0` for a guest request.
     *
     * The binding's session is kept by leaving it unrevoked, or, for an
     * access-only token, by leaving the identity's "tokens valid after" cutoff
     * where it is. The binding stays bound either way.
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
     * Revoke one session of the owner, found through the owner's `sessions()`
     * relation on the write connection, so another identity's session is not
     * found: `false`, without saying whether it exists. Returns whether this
     * call revoked it (`false` too for a session already revoked).
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
     * one (its pending sessions among them), and cancel its pending identifier
     * changes; when the identity records a "tokens valid after" cutoff, move it
     * to now first. Returns how many sessions this call revoked. The
     * `$committed` callback given runs once the revocation commits, before any
     * session it ended is reported.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $except
     * @param  ?\Closure(): void  $committed
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function revokeSessions(Identity $identity, RevocationReason $reason, ?Session $except = null, ?\Closure $committed = null): int
    {
        return $this->endSessions([$this->identityScope($identity)], $reason, $except, $committed);
    }

    /**
     * Revoke every session that acts as the principal, except the given one,
     * pending sessions that record it among them; when the principal records a
     * "tokens valid after" cutoff, move it to now first. Returns how many
     * sessions this call revoked.
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
     * The identity established its first password: end its sessions
     * (`password_established`), except the given session.
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
    public function passwordEstablished(Identity $identity, ?Session $except = null): int
    {
        return $this->revokeSessions($identity, RevocationReason::PASSWORD_ESTABLISHED, $except);
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
     * A first-factor credential of the identity (a passkey, or a phone number
     * or email address it signs in with) was removed: end its sessions
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
        return $this->revokeSessions($identity, RevocationReason::IDENTITY_DEACTIVATED);
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
        return $this->revokePrincipalSessions($principal, RevocationReason::PRINCIPAL_DEACTIVATED);
    }

    /**
     * The tenant was deactivated: end every session acting as one of the
     * principals listed for it, and every session acting in it whatever its
     * principal (its active tenant), as `tenant_deactivated`. Every principal
     * listed must belong to the tenant, or nothing is written and an
     * `InvalidArgumentException` is thrown; a principal listed twice counts
     * once, and so does a session both find. All sessions, pending ones among
     * them, are ended in one transaction, after each principal's cutoff moved,
     * with one `SignedOutEverywhere` per principal and one `SessionRevoked` per
     * session.
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

        return $this->endSessions([...$scopes, RevocationScope::activeTenant($tenant)], RevocationReason::TENANT_DEACTIVATED, null);
    }

    /**
     * Every session of the identity, with its pending identifier changes of
     * every type that has a normaliser (a change needs one), when its
     * identifiers can be changed.
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
     * End every session of the scopes, reporting each revoked session and then
     * each scope of an identity or a principal once the revocations commit,
     * after the `$committed` callback given; a tenant's scope signs no one out
     * everywhere, so it reports only its sessions.
     *
     * @param  non-empty-list<\SineMacula\Laravel\Authentication\Sessions\RevocationScope>  $scopes
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $except
     * @param  ?\Closure(): void  $committed
     * @return int
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    private function endSessions(array $scopes, RevocationReason $reason, ?Session $except, ?\Closure $committed = null): int
    {
        $client = $this->context->client();
        $guard  = $this->context->name();

        return $this->revocations->revokeScopes(
            $scopes,
            $reason,
            $except,
            CarbonImmutable::now()->startOfSecond(),
            function (EloquentSession&Model $session, RevocationScope $scope) use ($client, $reason): void {
                $method  = $session->getSignInMethod();
                $context = new EventContext($session->getGuard(), $client, $scope->identity, $scope->principal, $scope->tenant, $session, $method, fromSession: true);

                $this->context->dispatch(new SessionRevoked($context, $reason));
            },
            function (RevocationScope $scope, int $revoked, ?CarbonImmutable $cutoff) use ($client, $guard, $reason, $except): void {
                if ($scope->identity === null && $scope->principal === null) {
                    return;
                }

                $context = new EventContext($guard, $client, $scope->identity, $scope->principal, $scope->tenant, $except);

                $this->context->dispatch(new SignedOutEverywhere($context, $reason, $revoked, $cutoff));
            },
            $committed,
        );
    }

    /**
     * The binding's active tenant, or `null` when there is none or, bound by a
     * trusted bind, it cannot be loaded: a revocation is reported either way.
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
     * `WriteConnection::stored()` so a tenant relation set by whoever loaded
     * the principal (or eager-loaded from a replica) cannot stand in for the
     * stored one. A principal whose opted-in tenant cannot be loaded any more
     * (deleted, soft-deleted, hidden by a scope) acts within the tenant when
     * its `TenantUnavailableException` names that very tenant: its class and
     * key.
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
