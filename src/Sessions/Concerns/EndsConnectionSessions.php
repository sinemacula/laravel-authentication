<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Sessions\ConnectionRevocations;

/**
 * The session service's revocations by how a session began: the sessions an
 * external provider's connection established, when the connection is disabled
 * or deleted, and an identity's sessions through it, when its link to the
 * connection is removed, which `ConnectionRevocations` carries out.
 *
 * They are delegations with no state of their own but that one; they sit in a
 * trait only so the service stays within the number of methods one class may
 * declare.
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
     * The connection was disabled: end every live session it established, of
     * every guard, pending ones included (`connection_disabled`), unless
     * `authentication.revocation.connection_disabled` is `false`. Returns how
     * many sessions this call revoked. Call it in the transaction that disables
     * the connection, on the storage connection, so both commit or roll back
     * together; it runs as a savepoint there and reports each session once that
     * commits, when this guard, if it is bound to one of them, forgets it.
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
     * The connection was deleted: end every live session it established
     * (`connection_deleted`), as `connectionDisabled()` does, unless
     * `authentication.revocation.connection_deleted` is `false`.
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
     * The identity's link to the connection was removed: end every live session
     * of the identity the connection established (`link_removed`), unless
     * `authentication.revocation.link_removed` is `false`. The identity's other
     * sessions, and the connection's other identities', are left alone. When
     * this guard is bound to a session it ends, it forgets it once that
     * commits.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $connectionId
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function linkRemoved(Identity $identity, string $connectionId): int
    {
        return $this->connectionRevocations->link($identity, $connectionId, CarbonImmutable::now()->startOfSecond());
    }
}
