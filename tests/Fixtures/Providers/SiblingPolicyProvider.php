<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Resolvers\IdentityAsPrincipalResolver;
use Tests\Fixtures\Scopes\AdminRejectingScopeRegistry;

/**
 * Another package's provider that binds its own principal resolver,
 * additional-factor policy and scope registry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SiblingPolicyProvider extends ServiceProvider
{
    /**
     * Bind the policies.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->app->singleton(PrincipalResolver::class, IdentityAsPrincipalResolver::class);
        $this->app->singleton(AdditionalFactorPolicy::class, AlwaysRequireAdditionalFactor::class);
        $this->app->singleton(ScopeRegistry::class, AdminRejectingScopeRegistry::class);
    }
}
