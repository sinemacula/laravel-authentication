<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

/**
 * Lets an identity, principal or tenant report whether it is active.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface CanBeActive
{
    /**
     * Whether the model is currently eligible to authenticate.
     *
     * @return bool
     */
    public function isActive(): bool;
}
