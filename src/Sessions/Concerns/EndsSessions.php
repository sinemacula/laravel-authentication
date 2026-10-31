<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use Illuminate\Pagination\LengthAwarePaginator;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Sessions\ActiveDevices;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;

/**
 * The session service's device list, and its sign-out, revocation and
 * security-change methods, which `SessionRevocations` carries out: signing out
 * and signing out everywhere for the guard the service binds, the rest for
 * whatever identity, principal or tenant they are given.
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

    /**
     * One page of the identity's active devices, of every guard, for a device
     * list: most recently used first (never used last), then newest first, each
     * summarised without its digests, revocation or principal, and marked when
     * it is the device this guard is authenticated with for the request. Read
     * on the write connection through the identity's `devices()` relation.
     * `$perPage` is 1 to 100; the page is the request's `page` parameter unless
     * given.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  int  $perPage
     * @param  ?int  $page
     * @return \Illuminate\Pagination\LengthAwarePaginator<int, \SineMacula\Laravel\Authentication\Sessions\DeviceSummary>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function devices(Identity $identity, int $perPage = 15, ?int $page = null): LengthAwarePaginator
    {
        return ActiveDevices::page($identity, $this->guard->device(), $perPage, $page);
    }

    /**
     * Sign the request's session out: revoke the device the guard is bound to
     * (`signed_out`), dispatch Laravel's `Logout` when an identity was bound,
     * and forget the guard's state for the rest of the request. Returns whether
     * this call revoked a device.
     *
     * A session without a persisted device (an access-only token) has nothing
     * to revoke and is only forgotten; a guest request does nothing. The
     * browser's refresh cookie, if any, is the application's to clear.
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
        return $this->revocations->signOut($this->guard);
    }

    /**
     * End every session of the request's identity, of every guard, with reason
     * `signed_out_everywhere`, keeping the request's own session when asked.
     * Returns how many devices this call revoked; `0` for a guest request.
     *
     * The request's session is kept by keeping its device. A session without a
     * device (an access-only token) is kept by leaving the identity's "tokens
     * valid after" cutoff where it is, since a device-less token can only be
     * ended through it: its devices are still revoked, but the identity's other
     * device-less tokens then also keep working until they expire. The
     * identity's pending identifier changes are cancelled either way, since
     * none records the session it was requested from.
     *
     * The guard stays bound for the rest of the request either way; call
     * `signOut()` as well to end the request's own session.
     *
     * @param  bool  $keepCurrentDevice
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Throwable
     */
    public function signOutEverywhere(bool $keepCurrentDevice = false): int
    {
        return $this->revocations->signOutEverywhere($this->guard, $keepCurrentDevice);
    }

    /**
     * Revoke one device of the owner, found through the owner's `devices()`
     * relation on the write connection, so another identity's device is not
     * found: `false`, without saying whether it exists. Returns whether this
     * call revoked it (`false` too for a device already revoked).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $owner
     * @param  mixed  $deviceId
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @return bool
     *
     * @throws \LogicException
     *
     * @imperative
     */
    public function revokeDevice(Identity $owner, mixed $deviceId, RevocationReason $reason): bool
    {
        return $this->revocations->revokeDevice($owner, $deviceId, $reason);
    }

    /**
     * Revoke every device of the identity, of every guard, except the given
     * one, end its pending sign-ins, and cancel its pending identifier changes
     * (a change link needs no session); when the identity records a "tokens
     * valid after" cutoff, move it to now first, so its access tokens issued
     * without a device stop as well. Returns how many devices this call
     * revoked.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $except
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function revokeDevices(Identity $identity, RevocationReason $reason, ?Device $except = null): int
    {
        return $this->revocations->revokeDevices($identity, $reason, $except);
    }

    /**
     * Revoke every device whose session acts as the principal, except the given
     * one, and end the pending sign-ins that would act as it; when the
     * principal records a "tokens valid after" cutoff, move it to now first.
     * Returns how many devices this call revoked.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $except
     * @return int
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Throwable
     */
    public function revokePrincipalDevices(Principal $principal, RevocationReason $reason, ?Device $except = null): int
    {
        return $this->revocations->revokePrincipalDevices($principal, $reason, $except);
    }

    /**
     * The identity's password was changed: end its sessions
     * (`password_changed`), except on the given device, the one the change was
     * made from when the application keeps it signed in. Never call it for an
     * automatic rehash.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $except
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function passwordChanged(Identity $identity, ?Device $except = null): int
    {
        return $this->revocations->passwordChanged($identity, $except);
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
        return $this->revocations->passwordReset($identity);
    }

    /**
     * A factor the identity signs in with was removed: end its sessions
     * (`factor_removed`), except on the given device. The seam a further-factor
     * package calls when a factor is removed.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $except
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function factorRemoved(Identity $identity, ?Device $except = null): int
    {
        return $this->revocations->factorRemoved($identity, $except);
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
        return $this->revocations->identityDeactivated($identity);
    }

    /**
     * The principal was deactivated: end every session acting as it
     * (`principal_deactivated`).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return int
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Throwable
     */
    public function principalDeactivated(Principal $principal): int
    {
        return $this->revocations->principalDeactivated($principal);
    }

    /**
     * The tenant was deactivated: end every session acting as one of the
     * principals the application lists for it (`tenant_deactivated`), since
     * devices record principals, not tenants. Every principal must act within
     * the tenant (the same class and identifier, read on the write connection),
     * or nothing is written and an `InvalidArgumentException` is thrown; a
     * principal listed twice counts once. A tenant that opts into activation
     * (`CanBeActive`) and is already deleted or soft-deleted works too: a
     * principal whose `getTenant()` throws the `TenantUnavailableException`
     * naming it (its class, key name and key, as `ActsAsPrincipal` does) acts
     * within it. A tenant that does not opt in reads as no tenant once it
     * cannot be loaded, so call this before deleting it. All devices and
     * pending sign-ins are ended in one transaction, after each principal's
     * cutoff moved, with one `SignedOutEverywhere` per principal.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  iterable<\SineMacula\Laravel\Authentication\Contracts\Principal>  $principals
     * @return int
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Throwable
     */
    public function tenantDeactivated(Tenant $tenant, iterable $principals): int
    {
        return $this->revocations->tenantDeactivated($tenant, $principals);
    }
}
