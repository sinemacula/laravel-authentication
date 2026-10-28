<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Sessions\PrincipalReference;
use SineMacula\Laravel\Authentication\Sessions\RevocationScope;

/**
 * The session service's answers to security changes an application makes in its
 * own flows: each ends the affected sessions with its reason, as a bulk
 * revocation (see `ManagesDevices`), moving the scope's "tokens valid after"
 * cutoff when it records one and ending its pending sign-ins. Each returns how
 * many devices it revoked.
 *
 * Deactivation already stops every token at once through the live activity
 * checks; revoking makes the end outlast a reactivation and records why.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RevokesOnSecurityChanges
{
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
     * @throws \LogicException
     * @throws \Throwable
     */
    public function passwordChanged(Identity $identity, ?Device $except = null): int
    {
        return $this->revokeDevices($identity, RevocationReason::PASSWORD_CHANGED, $except);
    }

    /**
     * The identity's password was reset: end every session it has
     * (`password_reset`).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return int
     *
     * @throws \LogicException
     * @throws \Throwable
     */
    public function passwordReset(Identity $identity): int
    {
        return $this->revokeDevices($identity, RevocationReason::PASSWORD_RESET);
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
     * @throws \LogicException
     * @throws \Throwable
     */
    public function factorRemoved(Identity $identity, ?Device $except = null): int
    {
        return $this->revokeDevices($identity, RevocationReason::FACTOR_REMOVED, $except);
    }

    /**
     * The identity was deactivated: end every session it has
     * (`identity_deactivated`).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return int
     *
     * @throws \LogicException
     * @throws \Throwable
     */
    public function identityDeactivated(Identity $identity): int
    {
        return $this->revokeDevices($identity, RevocationReason::IDENTITY_DEACTIVATED);
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
        return $this->revokePrincipalDevices($principal, RevocationReason::PRINCIPAL_DEACTIVATED);
    }

    /**
     * The tenant was deactivated: end every session acting as one of the
     * principals the application lists for it (`tenant_deactivated`), since
     * devices record principals, not tenants. Every principal must act within
     * the tenant (the same class and identifier, read on the write connection),
     * or nothing is written and an `InvalidArgumentException` is thrown; a
     * principal listed twice counts once. A tenant that is already deleted or
     * soft-deleted works too: a principal naming it acts within it. All devices
     * and pending sign-ins are ended in one transaction, after each principal's
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
        $scopes = [];

        foreach ($principals as $principal) {

            self::assertActsWithin($principal, $tenant);

            $scopes[PrincipalReference::type($principal) . "\0" . PrincipalReference::id($principal)] ??= RevocationScope::principal($principal, $tenant);
        }

        return $scopes === [] ? 0 : $this->endSessions(array_values($scopes), RevocationReason::TENANT_DEACTIVATED, null);
    }

    /**
     * Refuse a principal that does not act within the tenant. A principal whose
     * tenant cannot be loaded any more (deleted, soft-deleted, hidden by a
     * scope) acts within the tenant when it names that very tenant: its class
     * and key.
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
            $actual = WriteConnection::during($principal, static fn (): ?Tenant => $principal->getTenant());
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
