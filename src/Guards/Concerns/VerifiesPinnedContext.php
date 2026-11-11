<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards\Concerns;

use Illuminate\Support\Carbon;
use SineMacula\Laravel\Authentication\Admission\PinnedPrincipal;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\SessionRecords\IdentitySessions;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;

/**
 * Proves that a principal or session pinned on `attempt()` belongs to the
 * identity signing in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \SineMacula\Laravel\Authentication\Guards\AbstractGuard
 */
trait VerifiesPinnedContext
{
    /**
     * Resolve a caller-supplied principal through the resolver's hinted path,
     * or `null` when the identity does not own it.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $pinned
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    protected function resolvePinnedPrincipal(Identity $identity, Principal $pinned): ?Principal
    {
        return PinnedPrincipal::resolve($this->context->resolver(), $identity, $pinned);
    }

    /**
     * Return the identity's live session the pinned one names, or `null` when
     * there is none acting as the principal.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $pinned
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \LogicException
     */
    protected function resolvePinnedSession(Identity $identity, Principal $principal, Session $pinned): ?Session
    {
        $owned = $this->resolveSessionFromHint($identity, $pinned->getSessionIdentifier());

        return $owned !== null && $owned::class === $pinned::class && OwnedSession::actsAs($owned, $principal) ? $owned : null;
    }

    /**
     * Resolve a live session of this guard for the identity from a pinned
     * session's identifier, or `null` when there is none.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  mixed  $hint
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Session
     *
     * @throws \LogicException
     */
    protected function resolveSessionFromHint(Identity $identity, mixed $hint): ?Session
    {
        $session = IdentitySessions::find($identity, $hint);

        return $session !== null && OwnedSession::refusal($session, $this->context->name(), Carbon::now()) === null ? $session : null;
    }
}
