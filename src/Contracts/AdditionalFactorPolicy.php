<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;

/**
 * Additional-factor policy contract.
 *
 * Asked about the identity, after the primary sign-in method has verified it
 * and the guard has admitted it, and before any principal is chosen, whether
 * the sign-in needs a further factor before its session may activate. The
 * package's default never requires one; an MFA package or the application binds
 * its own policy in the container. A tenant that asks more of a session says so
 * through the tenant authentication policy instead.
 *
 * When a factor is required, the session service issues no token: the session
 * is pending, with a short-lived pending credential that cannot authenticate a
 * request, until the factor's verifier hands it the factor's proof
 * (`satisfy()`). The policy is asked again each time the pending session is
 * acted on, and a stored accepted further factor or recovery code meets it.
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
