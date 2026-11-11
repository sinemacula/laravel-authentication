<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Admission;

use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * Asks the application policy whether it admits an identity by the identifier
 * type its sign-in used, on the write connection.
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
     * The policy's `admitIdentifier()` answer, asked on the write connection.
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
