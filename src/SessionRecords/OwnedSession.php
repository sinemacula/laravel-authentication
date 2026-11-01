<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\SessionRecords;

use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;

/**
 * Says whether a guard may authenticate on a session someone named (a `sid`
 * claim, a session pinned on `attempt()`), once `IdentitySessions::find()` has
 * found it among the identity's own sessions.
 *
 * The guard, revocation and deadline reads run inside
 * `WriteConnection::during()`, which pins every connection a model resolves
 * meanwhile, so a session that derives its state from a relation or another
 * table reads the writer as well.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class OwnedSession
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Why the guard may not authenticate on the session at the given time, or
     * `null` when it may: a session of another guard (or of none), a revoked
     * one, a pending one (it waits on requirements, so no token of it is
     * accepted until it activates), and one that has ended (past its idle or
     * absolute deadline, or without deadlines), in that order. The revocation,
     * the status and the deadlines are read whatever the guard, so a session
     * loaded without one of them is reported as the misconfiguration it is. The
     * deadlines are checked with no leeway, so a token cannot outlive its
     * session.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $guard
     * @param  \Carbon\CarbonInterface  $now
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \LogicException
     */
    public static function refusal(Session $session, string $guard, CarbonInterface $now): ?FailureReason
    {
        return WriteConnection::during($session, static function () use ($session, $guard, $now): ?FailureReason {

            $revoked = $session->getRevokedAt() !== null;
            $pending = $session->getStatus() === SessionStatus::PENDING;
            $ended   = SessionDeadlines::hasEnded($session, $now);

            return match (true) {
                $session->getGuard() !== $guard => FailureReason::SESSION_GUARD_MISMATCH,
                $revoked                        => FailureReason::SESSION_REVOKED,
                $pending                        => FailureReason::SESSION_PENDING,
                $ended                          => FailureReason::SESSION_EXPIRED,
                default                         => null,
            };
        });
    }

    /**
     * Whether the session acts as the principal: the session records that
     * principal's morph type and identifier, read from the row already loaded,
     * with no query. A session that records no principal, or that is not an
     * Eloquent session able to record one, acts as none.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return bool
     */
    public static function actsAs(Session $session, Principal $principal): bool
    {
        return $session instanceof EloquentSession && $session instanceof Model && PrincipalReference::isRecordedOn($session, $principal);
    }

    /**
     * Whether the session acts in the tenant a token names (its `tenant_id`):
     * the session records that tenant's identifier, or records none for a token
     * that names none.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  mixed  $tenantId
     * @return bool
     *
     * @throws \LogicException
     */
    public static function actsIn(Session $session, mixed $tenantId): bool
    {
        $recorded = WriteConnection::during($session, static fn (): ?string => $session->getTenantId());

        return $recorded === null ? $tenantId === null : IdentifierCoercion::matches($recorded, $tenantId);
    }

    /**
     * Whether a token issued at the given time (its `iat`) was issued at or
     * after the floor the session's last change of context set (see
     * `SwitchFloor`), so a token from before a switch, or before a return to
     * pending, cannot come back to life when the session comes back to that
     * context. A session whose context never changed accepts any time.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  mixed  $issuedAt
     * @return bool
     *
     * @throws \LogicException
     */
    public static function isIssuedSinceSwitch(Session $session, mixed $issuedAt): bool
    {
        $switched = WriteConnection::during($session, static fn (): ?CarbonInterface => $session->getSwitchedAt());

        return $switched === null || (is_int($issuedAt) && $issuedAt >= $switched->getTimestamp());
    }
}
