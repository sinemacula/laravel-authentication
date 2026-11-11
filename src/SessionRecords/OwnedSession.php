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
 * Says whether a guard may authenticate on a session someone named, once found
 * among the identity's own sessions.
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
     * `null` when it may.
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
     * Whether the session records the principal, read from the loaded row.
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
     * Whether the session acts in the tenant a token names (its `tenant_id`).
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
     * after the session's last change of context.
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
