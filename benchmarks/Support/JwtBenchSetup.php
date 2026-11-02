<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use SineMacula\Laravel\Authentication\Applications\AdmitAnyPrincipal;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Requirements\MeetNoRequirement;
use SineMacula\Laravel\Authentication\Tenancy\OwnTenantOnly;
use SineMacula\Laravel\Authentication\Tenancy\RequireNothingOfTenants;
use SineMacula\Laravel\Authentication\Tenancy\ResolveNoTenant;

/**
 * Shared configuration for the JWT bearer benchmarks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class JwtBenchSetup
{
    /**
     * Build the package config repository backing the benchmarks.
     *
     * @return \Illuminate\Config\Repository
     */
    public static function config(): ConfigRepository
    {
        return new ConfigRepository([
            'database'       => ['default' => BenchDatabase::CONNECTION],
            'authentication' => [
                'session' => [
                    'model'                      => Session::class,
                    'table'                      => 'authentication_sessions',
                    'last_used_throttle_seconds' => 60,
                ],
                'timebox' => [
                    'credentials_microseconds' => 400000,
                ],
            ],
        ]);
    }

    /**
     * Bind on a harness's own container the access, tenancy and requirement
     * defaults the service provider registers, which the bearer and refresh
     * paths resolve from the global container, and make it that container.
     *
     * @param  \Illuminate\Container\Container  $container
     * @return void
     */
    public static function bindPackageDefaults(Container $container): void
    {
        $container->singleton(ApplicationAccess::class, AdmitAnyPrincipal::class);
        $container->singleton(TenantAccess::class, OwnTenantOnly::class);
        $container->singleton(TenantResolver::class, ResolveNoTenant::class);
        $container->singleton(TenantAuthenticationPolicy::class, RequireNothingOfTenants::class);
        $container->singleton(RequirementCheck::class, MeetNoRequirement::class);

        Container::setInstance($container);
    }
}
