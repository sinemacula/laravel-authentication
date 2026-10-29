<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Contracts\Container\Container;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Factors\NeverRequireAdditionalFactor;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use Tests\Fixtures\Sessions\PermissiveAudiencePolicy;
use Tests\Fixtures\Sessions\UnlimitedAttemptLimiter;

/**
 * Binds permissive sign-in policies (every method allowed, every principal
 * admitted with the given lifetimes, no attempt limits, no further factor) for
 * guard tests that build guards over mocked collaborators without the package
 * service provider: no configuration describes their guards, so the shipped
 * policy and limiter could not serve them.
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
     * Bind the permissive sign-in policies.
     *
     * @param  \Illuminate\Contracts\Container\Container  $app
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @return void
     */
    protected static function bindSignInPolicyDoubles(Container $app, TokenLifetimes $lifetimes): void
    {
        $app->instance(AudiencePolicy::class, new PermissiveAudiencePolicy($lifetimes));
        $app->singleton(AttemptLimiter::class, UnlimitedAttemptLimiter::class);
        $app->singleton(AdditionalFactorPolicy::class, NeverRequireAdditionalFactor::class);
    }
}
