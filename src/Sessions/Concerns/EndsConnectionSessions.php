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
 * or deleted, and an identity's sessions through one link, when the link is
 * removed or its scope is widened, which `ConnectionRevocations` carries out.
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
     * together; it runs as a savepoint there and, once that commits, this
     * guard, if it is bound to one of the sessions, forgets it before each is
     * reported. It finds the sessions with locking reads, so it sees one a
     * sign-in through the connection committed while that transaction waited
     * for its lock on the connection; on PostgreSQL, whose reads at REPEATABLE
     * READ or SERIALIZABLE see only the transaction's first snapshot, that
     * transaction must run at READ COMMITTED (a `LogicException` otherwise,
     * before anything is read).
     *
     * @param  string  $connectionId
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
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
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function connectionDeleted(string $connectionId): int
    {
        return $this->connectionRevocations->connection($connectionId, RevocationReason::CONNECTION_DELETED, CarbonImmutable::now()->startOfSecond());
    }

    /**
     * The identity's link through the connection was removed: end every live
     * session of the identity established through that link, the connection and
     * the link id both recorded on its provenance exactly as given
     * (`link_removed`), unless `authentication.revocation.link_removed` is
     * `false`. The identity's sessions through its other links, of this
     * connection or another, its other sessions, and other identities' are left
     * alone. Call it in the transaction that removes the link, on the storage
     * connection, at READ COMMITTED on PostgreSQL, as `connectionDisabled()`
     * says; when this guard is bound to a session it ends, it forgets it once
     * that commits.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $connectionId
     * @param  string  $linkId
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function linkRemoved(Identity $identity, string $connectionId, string $linkId): int
    {
        return $this->connectionRevocations->link($identity, $connectionId, $linkId, RevocationReason::LINK_REMOVED, CarbonImmutable::now()->startOfSecond());
    }

    /**
     * The scope of the identity's link through the connection was widened, so
     * the link may now act for more than its sessions were established for: end
     * every live session of the identity established through that link, as
     * `linkRemoved()` finds them (`link_scope_widened`). Mandatory: no setting
     * turns it off. Call it synchronously in the transaction that widens the
     * scope, on the storage connection (at READ COMMITTED on PostgreSQL), so
     * both commit or roll back together; it runs as a savepoint there. Calling
     * it twice for one widening is safe: the second call finds nothing live
     * left to end, revokes nothing and reports nothing.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $connectionId
     * @param  string  $linkId
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function linkScopeWidened(Identity $identity, string $connectionId, string $linkId): int
    {
        return $this->connectionRevocations->link($identity, $connectionId, $linkId, RevocationReason::LINK_SCOPE_WIDENED, CarbonImmutable::now()->startOfSecond());
    }
}
