<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Factors;

use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;

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
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     */
    #[\Override]
    public function requirementFor(AdditionalFactorContext $context): Requirement
    {
        unset($context);

        return new Requirement(new RequirementPart);
    }
}
