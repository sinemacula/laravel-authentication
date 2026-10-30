<?php

declare(strict_types = 1);

namespace Tests\Integration\Providers;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use Tests\Fixtures\Providers\SiblingPolicyProvider;

/**
 * The policies another package binds hold when its provider registers before
 * the package's: the package's defaults do not replace them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationServiceProvider::class)]
final class SiblingPoliciesRegisteredFirstTest extends SiblingPoliciesTestCase
{
    /**
     * Register the sibling's provider, then the package's.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [SiblingPolicyProvider::class, AuthenticationServiceProvider::class];
    }
}
