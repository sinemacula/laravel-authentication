<?php

declare(strict_types = 1);

namespace Tests\Integration\Providers;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use Tests\Fixtures\Providers\SiblingPolicyProvider;

/**
 * The policies another package binds hold when its provider registers after the
 * package's: they replace the package's defaults.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationServiceProvider::class)]
final class SiblingPoliciesRegisteredLastTest extends SiblingPoliciesTestCase
{
    /**
     * Register the package's provider, then the sibling's.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [AuthenticationServiceProvider::class, SiblingPolicyProvider::class];
    }
}
