<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Concerns;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * The session service's revocations when an identity or a principal is deleted,
 * which `SessionRevocations` carries out.
 *
 * They are delegations with no state of their own; they sit in a trait only so
 * the service stays within the number of methods one class may declare.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait EndsSessionsOnDeletion
{
    /**
     * The identity was deleted, or soft-deleted: end every session it has, of
     * every guard, pending ones included (`identity_deleted`), and cancel its
     * pending identifier changes. It works on the model as it was deleted,
     * which keeps its key, as well as on one about to be. Calling it again is
     * safe: it revokes only a session written since. While the identity is a
     * model loaded from its row (soft-deleted, or not yet deleted), each call
     * moves its "tokens valid after" cutoff, when it records one, forward to
     * now.
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
        return $this->revocations->identityDeleted($identity);
    }

    /**
     * The principal was deleted, or soft-deleted: end every session acting as
     * it, pending ones included (`principal_deleted`), as `identityDeleted()`
     * does for an identity: on the model as it was deleted, safely again, and
     * moving its cutoff while it is loaded from its row.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return int
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function principalDeleted(Principal $principal): int
    {
        return $this->revocations->principalDeleted($principal);
    }
}
