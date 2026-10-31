<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Admission;

use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * Asks the application policy whether it admits an identity, or an identity as
 * a principal, with the policy's reads pinned to the write connection.
 *
 * A policy that keeps principals out of an application decides from rows of its
 * own (a grant, a membership, a flag), and a read replica can lag behind the
 * change that withdrew one, so an answer read from it could admit someone the
 * primary already keeps out. Each question runs inside
 * `WriteConnection::during()` for the identity, and `admit()` for the principal
 * as well, so every model read the policy makes, and every query-builder read
 * on the identity's or the principal's connection, sees the primary. A
 * query-builder read on any other connection pins itself.
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

    /**
     * The policy's `admit()` answer, asked on the write connection for the
     * identity and for the principal.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy  $policy
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?string  $identifierType
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function admit(ApplicationPolicy $policy, string $guard, Identity $identity, Principal $principal, ?string $identifierType): ?FailureReason
    {
        return WriteConnection::during($identity, static fn (): ?FailureReason => WriteConnection::during(
            $principal,
            static fn (): ?FailureReason => $policy->admit($guard, $identity, $principal, $identifierType),
        ));
    }
}
