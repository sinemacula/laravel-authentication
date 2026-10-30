<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Facades\Auth;

/**
 * A queued job that records, when it runs, what the `api` guard's settings are
 * as the package sees them: the access token lifetime of its token service,
 * whether its audience allows the password method, and which guard instance
 * serves it. Each run appends to the `observed.configuration` binding.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ObserveConfigurationJob implements ShouldQueue
{
    use Dispatchable, Queueable;

    /**
     * Append this run's observation.
     *
     * @return void
     */
    public function handle(): void
    {
        $observed = app()->bound('observed.configuration') ? app('observed.configuration') : [];

        assert(is_array($observed));

        $observed[] = [
            'access_ttl_minutes' => Auth::jwt('api')->lifetimes()->accessTtlMinutes,
            'allows_password'    => app(AudiencePolicy::class)->allowsMethod('api', 'password'),
            'guard'              => spl_object_id(Auth::guard('api')),
        ];

        app()->instance('observed.configuration', $observed);
    }
}
