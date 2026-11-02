<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Admission;

use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * Asks the application policy whether it admits an identity with the type of
 * identifier its sign-in used, with the policy's reads pinned to the write
 * connection.
 *
 * A policy that holds identities to a rule of its own (an identifier recorded
 * verified, say) decides from rows of its own, and a read replica can lag
 * behind the change that withdrew one, so an answer read from it could admit
 * someone the primary already keeps out. The question runs inside
 * `WriteConnection::during()` for the identity, so every model read the policy
 * makes, and every query-builder read on the identity's connection, sees the
 * primary. A query-builder read on any other connection pins itself. Whether a
 * principal may use the application is `ApplicationAccess`'s answer
 * (`PrincipalAdmission`).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ApplicationAdmission
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The policy's `admitIdentifier()` answer, asked on the write connection
     * for the identity.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy  $policy
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $identifierType
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function admitIdentifier(ApplicationPolicy $policy, string $guard, Identity $identity, ?string $identifierType): ?FailureReason
    {
        return WriteConnection::during($identity, static fn (): ?FailureReason => $policy->admitIdentifier($guard, $identity, $identifierType));
    }
}
