<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Factors;

use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;

/**
 * The package's default additional-factor policy: no sign-in needs a further
 * factor. Bind another `AdditionalFactorPolicy` to require one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NeverRequireAdditionalFactor implements AdditionalFactorPolicy
{
    /**
     * Never require a further factor.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
     * @return bool
     */
    #[\Override]
    public function requiresAdditionalFactor(AdditionalFactorContext $context): bool
    {
        return false;
    }
}
