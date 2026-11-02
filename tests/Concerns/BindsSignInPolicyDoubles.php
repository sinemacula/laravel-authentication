<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Applications\AdmitAnyPrincipal;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Factors\NeverRequireAdditionalFactor;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Requirements\MeetNoRequirement;
use SineMacula\Laravel\Authentication\Tenancy\OwnTenantOnly;
use SineMacula\Laravel\Authentication\Tenancy\RequireNothingOfTenants;
use SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant;
use Tests\Fixtures\Sessions\PermissiveApplicationPolicy;
use Tests\Fixtures\Sessions\UnlimitedAttemptLimiter;

/**
 * Binds permissive sign-in policies (every method allowed, every identity
 * admitted with the given lifetimes, no attempt limits, no further factor, no
 * tenant requirement) and the package's default access contracts (any principal
 * in any application, in its own tenant only) for guard tests that build guards
 * over mocked collaborators without the package service provider: no
 * configuration describes their guards, so the shipped policy and limiter could
 * not serve them.
 *
 * A trait rather than a base-class method because those tests extend different
 * base cases.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait BindsSignInPolicyDoubles
{
    /**
     * Bind the permissive sign-in policies and the default access contracts.
     *
     * @param  \Illuminate\Contracts\Container\Container  $app
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @return void
     */
    protected static function bindSignInPolicyDoubles(Container $app, TokenLifetimes $lifetimes): void
    {
        $app->instance(ApplicationPolicy::class, new PermissiveApplicationPolicy($lifetimes));
        $app->singleton(AttemptLimiter::class, UnlimitedAttemptLimiter::class);
        $app->singleton(AdditionalFactorPolicy::class, NeverRequireAdditionalFactor::class);
        $app->singleton(TenantAuthenticationPolicy::class, RequireNothingOfTenants::class);
        $app->singleton(RequirementCheck::class, MeetNoRequirement::class);
        $app->singleton(ApplicationAccess::class, AdmitAnyPrincipal::class);
        $app->singleton(TenantAccess::class, OwnTenantOnly::class);
        $app->singleton(TenantResolver::class, ResolveNoTenant::class);
    }
}
