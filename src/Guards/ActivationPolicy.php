<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards;

use SineMacula\Laravel\Authentication\Contracts\CanBeActive;

/**
 * The package's activation policy, shared by the credential, bearer-token and
 * refresh paths.
 *
 * Activation is an opt-in capability: a model is active unless it implements
 * `CanBeActive` and reports otherwise, so an ordinary model with no activation
 * column always authenticates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ActivationPolicy
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether the subject (an identity, principal, or tenant) may authenticate.
     * Returns `true` for subjects that do not implement `CanBeActive`.
     *
     * @param  object  $subject
     * @return bool
     */
    public static function isActive(object $subject): bool
    {
        return !$subject instanceof CanBeActive || $subject->isActive();
    }
}
