<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Sessions\ConnectionRevocations;

/**
 * The session service's revocations of the sessions an external provider's
 * connection or link established.
 *
 * Kept in a trait only to hold the service under the per-class method limit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait EndsConnectionSessions
{
    /** @var \SineMacula\Laravel\Authentication\Sessions\ConnectionRevocations Ends the sessions a connection established. */
    private readonly ConnectionRevocations $connectionRevocations;

    /**
     * End every live session the disabled connection established, inside the
     * transaction that disables it, returning how many were revoked.
     *
     * @param  string  $connectionId
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function connectionDisabled(string $connectionId): int
    {
        return $this->connectionRevocations->connection($connectionId, RevocationReason::CONNECTION_DISABLED, CarbonImmutable::now()->startOfSecond());
    }

    /**
     * End every live session the deleted connection established, as
     * `connectionDisabled()` does.
     *
     * @param  string  $connectionId
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function connectionDeleted(string $connectionId): int
    {
        return $this->connectionRevocations->connection($connectionId, RevocationReason::CONNECTION_DELETED, CarbonImmutable::now()->startOfSecond());
    }

    /**
     * End every live session of the identity established through the removed
     * link, inside the transaction that removes it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $connectionId
     * @param  string  $linkId
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function linkRemoved(Identity $identity, string $connectionId, string $linkId): int
    {
        return $this->connectionRevocations->link($identity, $connectionId, $linkId, RevocationReason::LINK_REMOVED, CarbonImmutable::now()->startOfSecond());
    }

    /**
     * End every live session of the referenced identity established through the
     * removed link, as `linkRemoved()` does, whether or not it is still stored
     * or in scope.
     *
     * @param  string  $identityType
     * @param  string  $identityId
     * @param  string  $connectionId
     * @param  string  $linkId
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function linkRemovedByReference(string $identityType, string $identityId, string $connectionId, string $linkId): int
    {
        $now = CarbonImmutable::now()->startOfSecond();

        return $this->connectionRevocations->linkByReference($identityType, $identityId, $connectionId, $linkId, RevocationReason::LINK_REMOVED, $now);
    }

    /**
     * End every live session of the identity established through the widened
     * link, inside the transaction that widens it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $connectionId
     * @param  string  $linkId
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function linkScopeWidened(Identity $identity, string $connectionId, string $linkId): int
    {
        return $this->connectionRevocations->link($identity, $connectionId, $linkId, RevocationReason::LINK_SCOPE_WIDENED, CarbonImmutable::now()->startOfSecond());
    }

    /**
     * End every live session of the referenced identity established through the
     * widened link, as `linkScopeWidened()` does, whether or not it is still
     * stored or in scope.
     *
     * @param  string  $identityType
     * @param  string  $identityId
     * @param  string  $connectionId
     * @param  string  $linkId
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function linkScopeWidenedByReference(string $identityType, string $identityId, string $connectionId, string $linkId): int
    {
        $now = CarbonImmutable::now()->startOfSecond();

        return $this->connectionRevocations->linkByReference($identityType, $identityId, $connectionId, $linkId, RevocationReason::LINK_SCOPE_WIDENED, $now);
    }
}
