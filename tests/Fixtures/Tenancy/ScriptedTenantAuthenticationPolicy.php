<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Tenancy;

use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;

/**
 * Tenant authentication policy that answers a scripted requirement and keeps
 * every context it was asked about.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScriptedTenantAuthenticationPolicy implements TenantAuthenticationPolicy
{
    /** @var list<\SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext> The contexts it was asked about, in order. */
    public array $asked = [];

    /** @var ?\Closure(\SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext): \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement The answer per tenant, if the test gives one. */
    public ?\Closure $answer = null;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement  $requirement
     */
    public function __construct(

        /** The requirement it answers with. */
        public TenantRequirement $requirement = new TenantRequirement,
    ) {}

    /**
     * Answer with the scripted requirement, keeping the context.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext  $context
     * @return \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement
     */
    #[\Override]
    public function requirementFor(TenantPolicyContext $context): TenantRequirement
    {
        $this->asked[] = $context;

        return $this->answer === null ? $this->requirement : ($this->answer)($context);
    }
}
