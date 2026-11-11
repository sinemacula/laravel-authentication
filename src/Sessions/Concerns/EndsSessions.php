<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Pagination\LengthAwarePaginator;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Sessions\ActiveSessions;
use SineMacula\Laravel\Authentication\Sessions\FactorChangeResult;
use SineMacula\Laravel\Authentication\Sessions\FactorRemoval;
use SineMacula\Laravel\Authentication\Sessions\FactorRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionSignOut;
use SineMacula\Laravel\Authentication\Sessions\SignOutResult;
use SineMacula\Laravel\Authentication\Sessions\TenantPolicyChanges;

/**
 * The session service's session list, and its sign-out, revocation and
 * security-change methods.
 *
 * Kept in a trait only to hold the service under the per-class method limit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait EndsSessions
{
    /** @var \SineMacula\Laravel\Authentication\Sessions\SessionRevocations Signs sessions out and ends them, on the guard's context. */
    private readonly SessionRevocations $revocations;

    /** @var \SineMacula\Laravel\Authentication\Sessions\TenantPolicyChanges Applies a tenant's changed authentication policy to its sessions. */
    private readonly TenantPolicyChanges $policyChanges;

    /** @var \SineMacula\Laravel\Authentication\Sessions\SessionSignOut Signs sessions out by their refresh credential. */
    private readonly SessionSignOut $signOuts;

    /** @var \SineMacula\Laravel\Authentication\Sessions\FactorRevocations Ends sessions when the factor package removes or resets factors, and judges the current session again after its changes. */
    private readonly FactorRevocations $factorRevocations;

    /**
     * One page of the identity's active sessions, of every guard, most recently
     * used first.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  int  $perPage
     * @param  ?int  $page
     * @return \Illuminate\Pagination\LengthAwarePaginator<int, \SineMacula\Laravel\Authentication\Sessions\SessionSummary>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function sessions(Identity $identity, int $perPage = 15, ?int $page = null): LengthAwarePaginator
    {
        return ActiveSessions::page($identity, $this->binding->session(), $perPage, $page);
    }

    /**
     * Sign the request's session out and forget the guard's state, returning
     * whether a session was revoked.
     *
     * @return bool
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     *
     * @imperative
     */
    public function signOut(): bool
    {
        return $this->revocations->signOut($this->binding);
    }

    /**
     * Sign out by the refresh credential presented, so a client whose access
     * token has expired can still sign out.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  int|string|null  $expectedSession
     * @return \SineMacula\Laravel\Authentication\Sessions\SignOutResult
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     *
     * @imperative
     */
    public function signOutWith(
        #[\SensitiveParameter] FailureReason|PresentedRefreshToken|null $presented,
        ClientContext $client,
        int|string|null $expectedSession = null,
    ): SignOutResult {
        return $this->signOuts->signOutWith($presented, $client, $expectedSession);
    }

    /**
     * End every session of the request's identity, of every guard, keeping the
     * request's own session when asked.
     *
     * @param  bool  $keepCurrentSession
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Throwable
     */
    public function signOutEverywhere(bool $keepCurrentSession = false): int
    {
        return $this->revocations->signOutEverywhere($this->binding, $keepCurrentSession);
    }

    /**
     * Revoke one session of the owner, returning whether this call revoked it.
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
        return $this->revocations->revokeSession($owner, $sessionId, $reason);
    }

    /**
     * Revoke every session of the identity, of every guard, except the given
     * one, and cancel its pending identifier changes.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $except
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function revokeSessions(Identity $identity, RevocationReason $reason, ?Session $except = null): int
    {
        return $this->revocations->revokeSessions($identity, $reason, $except);
    }

    /**
     * Revoke every session that acts as the principal, except the given one.
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
        return $this->revocations->revokePrincipalSessions($principal, $reason, $except);
    }

    /**
     * End the identity's sessions after a password change, except the given
     * session. Never call it for an automatic rehash.
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
        return $this->revocations->passwordChanged($identity, $except);
    }

    /**
     * End every session of the identity after a password reset.
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
        return $this->revocations->passwordReset($identity);
    }

    /**
     * End the identity's sessions after a first-factor credential was removed,
     * except the given session.
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
        return $this->revocations->credentialRemoved($identity, $except);
    }

    /**
     * End every session of the identity but `$current` after the factor package
     * removed a factor, and judge `$current` again without it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $factor
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $current
     * @return \SineMacula\Laravel\Authentication\Sessions\FactorRemoval
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function factorRemoved(Identity $identity, string $factor, ?Session $current = null): FactorRemoval
    {
        return $this->factorRevocations->remove($identity, $factor, $current, CarbonImmutable::now()->startOfSecond());
    }

    /**
     * Judge `$current` again after the factor package changed the identity's
     * factors without removing one.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Factors\Enums\FactorChangeMade  $change
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $current
     * @return \SineMacula\Laravel\Authentication\Sessions\FactorChangeResult
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function factorChanged(Identity $identity, FactorChangeMade $change, Session $current): FactorChangeResult
    {
        return $this->factorRevocations->change($identity, $change, $current, CarbonImmutable::now()->startOfSecond());
    }

    /**
     * End every session of the identity after the factor package reset its
     * further factors.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function factorReset(Identity $identity): int
    {
        return $this->factorRevocations->reset($identity);
    }

    /**
     * End every session of the deactivated identity.
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
        return $this->revocations->identityDeactivated($identity);
    }

    /**
     * End every session acting as the deactivated principal.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return int
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function principalDeactivated(Principal $principal): int
    {
        return $this->revocations->principalDeactivated($principal);
    }

    /**
     * End every session acting in the deactivated tenant or as one of the given
     * principals.
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
        return $this->revocations->tenantDeactivated($tenant, $principals);
    }

    /**
     * Apply a change of the tenant's authentication policy to the live sessions
     * acting in it, returning how many were revoked.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @return int
     *
     * @throws \Throwable
     */
    public function tenantPolicyChanged(Tenant $tenant): int
    {
        return $this->policyChanges->apply($tenant, CarbonImmutable::now()->startOfSecond());
    }
}
