<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Auth\Events\Logout;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Pagination\LengthAwarePaginator;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\ActiveDevices;
use SineMacula\Laravel\Authentication\Sessions\DeviceRevocations;
use SineMacula\Laravel\Authentication\Sessions\IdentityDevices;
use SineMacula\Laravel\Authentication\Sessions\RevocationScope;

/**
 * The session service's device management: listing an identity's active
 * devices, signing the current session out, and revoking one device or every
 * device of an identity or a principal.
 *
 * Every revocation marks the device (`revoked_at`, `revoked_reason`) with one
 * conditional update that only applies while it is not revoked yet: idempotent,
 * the first revocation's time and reason kept, and only the call that changed
 * the row reporting `DeviceRevoked`, once the revocation is committed on the
 * device's own connection. A bulk revocation reports each device it revoked and
 * then `SignedOutEverywhere`, also when it revoked none. The service builds the
 * revocations in its constructor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ManagesDevices
{
    /** @var \SineMacula\Laravel\Authentication\Sessions\DeviceRevocations Revokes one device or every device of a scope, and reports it once committed. */
    private readonly DeviceRevocations $revocations;

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
        $identity = $this->guard->user();
        $device   = $this->guard->device();
        $revoked  = false;

        if ($device instanceof EloquentDevice && $device instanceof Model) {

            $event = new DeviceRevoked(
                new EventContext(
                    $device->getGuard(),
                    $this->client(),
                    $identity,
                    $this->guard->principal(),
                    $this->boundTenant(),
                    $device,
                    $device->getSignInMethod(),
                    fromDevice: true,
                ),
                RevocationReason::SIGNED_OUT,
            );

            $revoked = $this->revocations->revoke($device, RevocationReason::SIGNED_OUT, CarbonImmutable::now()->startOfSecond(), fn () => $this->dispatch($event));
        }

        if ($identity !== null) {
            $this->dispatch(new Logout($this->guard->getName(), $identity));
        }

        $this->guard->forgetUser();

        return $revoked;
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
     * device-less tokens then also keep working until they expire.
     *
     * The guard stays bound for the rest of the request either way; call
     * `signOut()` as well to end the request's own session.
     *
     * @param  bool  $keepCurrentDevice
     * @return int
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     * @throws \Throwable
     */
    public function signOutEverywhere(bool $keepCurrentDevice = false): int
    {
        $identity = $this->guard->user();

        if ($identity === null) {
            return 0;
        }

        $device = $keepCurrentDevice ? $this->guard->device() : null;
        $scope  = RevocationScope::identity($identity);

        return $this->endSessions([$keepCurrentDevice && $device === null ? $scope->keepingCutoff() : $scope], RevocationReason::SIGNED_OUT_EVERYWHERE, $device);
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
        $device = IdentityDevices::find($owner, $deviceId);

        if ($device === null) {
            return false;
        }

        $event = new DeviceRevoked(new EventContext($device->getGuard(), $this->client(), $owner, device: $device, method: $device->getSignInMethod(), fromDevice: true), $reason);

        return $this->revocations->revoke($device, $reason, CarbonImmutable::now()->startOfSecond(), fn () => $this->dispatch($event));
    }

    /**
     * Revoke every device of the identity, of every guard, except the given
     * one, and end its pending sign-ins; when the identity records a "tokens
     * valid after" cutoff, move it to now first, so its access tokens issued
     * without a device stop as well. Returns how many devices this call
     * revoked.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $except
     * @return int
     *
     * @throws \LogicException
     * @throws \Throwable
     */
    public function revokeDevices(Identity $identity, RevocationReason $reason, ?Device $except = null): int
    {
        return $this->endSessions([RevocationScope::identity($identity)], $reason, $except);
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
        return $this->endSessions([RevocationScope::principal($principal)], $reason, $except);
    }

    /**
     * End every session of the scopes, reporting each revoked device and then
     * each scope once the revocations commit.
     *
     * @param  non-empty-list<\SineMacula\Laravel\Authentication\Sessions\RevocationScope>  $scopes
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\RevocationReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $except
     * @return int
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Throwable
     */
    private function endSessions(array $scopes, RevocationReason $reason, ?Device $except): int
    {
        $client = $this->client();
        $guard  = $this->guard->getName();

        return $this->revocations->revokeScopes(
            $scopes,
            $reason,
            $except,
            CarbonImmutable::now()->startOfSecond(),
            function (EloquentDevice&Model $device, RevocationScope $scope) use ($client, $reason): void {
                $method  = $device->getSignInMethod();
                $context = new EventContext($device->getGuard(), $client, $scope->identity, $scope->principal, $scope->tenant, $device, $method, fromDevice: true);

                $this->dispatch(new DeviceRevoked($context, $reason));
            },
            function (RevocationScope $scope, int $revoked, ?CarbonImmutable $cutoff) use ($client, $guard, $reason, $except): void {
                $context = new EventContext($guard, $client, $scope->identity, $scope->principal, $scope->tenant, $except);

                $this->dispatch(new SignedOutEverywhere($context, $reason, $revoked, $cutoff));
            },
        );
    }

    /**
     * The tenant the guard's bound principal acts within, or `null` when there
     * is none or it cannot be loaded. A principal loaded without the tenant's
     * key is a misconfiguration, and its `LogicException` propagates.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Tenant
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function boundTenant(): ?Tenant
    {
        try {
            return $this->guard->tenant();
        } catch (TenantUnavailableException) {
            return null;
        }
    }

    /**
     * The client of the request the guard serves.
     *
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    private function client(): ClientContext
    {
        return ClientContext::fromRequest($this->guard->getRequest());
    }
}
