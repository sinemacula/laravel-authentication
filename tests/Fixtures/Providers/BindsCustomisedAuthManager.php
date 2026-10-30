<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use Tests\Fixtures\Auth\CustomisedAuthManager;

/**
 * An application's provider that binds `auth` to its own subclass of the
 * package's auth manager while registering.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BindsCustomisedAuthManager extends ServiceProvider
{
    /**
     * Bind `auth` to the manager.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        $this->app->singleton('auth', static fn (Application $app): AuthManager => new CustomisedAuthManager($app));
    }
}
