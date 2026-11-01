<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Admission;

use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * Whether a principal may hold a session of an application.
 *
 * Interim: the access contracts are built alongside, and this body is replaced
 * by theirs; it throws until then, so it can never pass for an answer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PrincipalAdmission
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * `null` when the principal may hold a session of the application (it is
     * active, its own tenant is active, and the application access contract
     * lets it use the application), else `principal_inactive`,
     * `tenant_inactive` or `principal_ineligible`. Read on the write
     * connection.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \LogicException
     */
    public static function refusal(string $guard, Principal $principal): ?FailureReason
    {
        throw new \LogicException(sprintf('PrincipalAdmission::refusal() for %s on %s is not built yet.', $principal::class, $guard));
    }
}
