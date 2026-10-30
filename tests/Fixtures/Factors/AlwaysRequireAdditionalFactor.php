<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;

/**
 * Additional-factor policy that asks a further factor of every sign-in, as a
 * factor package's would for an identity that enrolled one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AlwaysRequireAdditionalFactor implements AdditionalFactorPolicy
{
    /**
     * Ask for a further factor.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
     * @return bool
     */
    #[\Override]
    public function requiresAdditionalFactor(AdditionalFactorContext $context): bool
    {
        unset($context);

        return true;
    }
}
