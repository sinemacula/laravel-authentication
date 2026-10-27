<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;

/**
 * Additional-factor policy contract.
 *
 * Asked after the primary sign-in method has verified the identity and the
 * guard has admitted it, whether the sign-in needs a further factor before a
 * session may start. The package's default never requires one; an MFA package
 * or the application binds its own policy in the container.
 *
 * When a factor is required, the session service starts no session: it hands
 * out a short-lived, single-use pending sign-in that cannot authenticate a
 * request, which the factor's verifier completes once the factor is proven.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AdditionalFactorPolicy
{
    /**
     * Whether the sign-in needs a further factor.
     *
     * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
     * @return bool
     */
    public function requiresAdditionalFactor(AdditionalFactorContext $context): bool;
}
