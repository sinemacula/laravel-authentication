<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Contracts\Support\DeferrableProvider;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;

/**
 * A factor package's deferred provider, which binds its additional-factor
 * policy only when the policy is first resolved.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class DeferredFactorPolicyProvider extends ServiceProvider implements DeferrableProvider
{
    /**
     * Bind the policy.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->app->singleton(AdditionalFactorPolicy::class, AlwaysRequireAdditionalFactor::class);
    }

    /**
     * The services the provider binds.
     *
     * @return list<string>
     */
    #[\Override]
    public function provides(): array
    {
        return [AdditionalFactorPolicy::class];
    }
}
