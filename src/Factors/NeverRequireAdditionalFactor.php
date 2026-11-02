<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Factors;

use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Requirements\Requirement;

/**
 * The package's default additional-factor policy: no sign-in needs anything
 * beyond its first factor. Bind another `AdditionalFactorPolicy` to require
 * more.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class NeverRequireAdditionalFactor implements AdditionalFactorPolicy
{
    /**
     * Require nothing.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     */
    #[\Override]
    public function requirementFor(AdditionalFactorContext $context): Requirement
    {
        return new Requirement;
    }
}
