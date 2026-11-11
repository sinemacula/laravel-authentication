<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Requirements\Requirement;

/**
 * Decides what a session's authentication must include beyond the identity's
 * first factor.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AdditionalFactorPolicy
{
    /**
     * What the session's authentication must include beyond its first factor.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
     * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
     */
    public function requirementFor(AdditionalFactorContext $context): Requirement;
}
