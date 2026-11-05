<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Context\ContributionSubject;

/**
 * Authentication context contributor contract.
 *
 * Adds keys of its own to the authentication context, under the namespace it is
 * registered with (`Context\ContextContributors::register()`). It is asked once
 * each time a context is built, after the package's own keys are worked out,
 * and is given them with the live identity, principal, tenant and session, and
 * the session's external provenance, counting proofs and first factor on
 * request. It reads only: a contributor that asks for the context being built
 * (`Auth::context()`) gets a `LogicException`, and an exception it throws
 * reaches the caller, since a policy cannot be judged on part of a context.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface AuthenticationContextContributor
{
    /**
     * The keys to add, by name without the namespace: each a lower-case letter
     * and then up to 63 lower-case letters, digits or underscores, each value
     * `null`, a scalar or an array of them (nested), never an object. Anything
     * else fails loudly with a `LogicException` naming the namespace and key.
     *
     * @param  \SineMacula\Laravel\Authentication\Context\ContributionSubject  $subject
     * @return array<string, mixed>
     */
    public function contribute(ContributionSubject $subject): array;
}
