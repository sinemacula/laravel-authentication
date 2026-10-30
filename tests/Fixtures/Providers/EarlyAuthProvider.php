<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Providers;

use Illuminate\Auth\EloquentUserProvider;
use Illuminate\Auth\GenericUser;
use Illuminate\Auth\RequestGuard;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

/**
 * Another package's provider that uses Laravel's auth manager, through the
 * facade, before the package's provider boots: it registers a guard driver
 * (`early`), a request guard driver (`early_request`), a user provider driver
 * (`early`) and a user resolver while registering, and resolves the default
 * guard while booting.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class EarlyAuthProvider extends ServiceProvider
{
    /** @var string Identifier of the user the resolver resolves. */
    public const string USER = 'resolved-early';

    /**
     * Register the drivers and the user resolver.
     *
     * @return void
     */
    #[\Override]
    public function register(): void
    {
        Auth::provider('early', static function (Application $app, array $config): UserProvider {

            $model = is_string($config['model'] ?? null) ? $config['model'] : '';

            return new EloquentUserProvider($app->make(Hasher::class), $model);
        });

        Auth::extend('early', static function (Application $app, string $name, array $config): RequestGuard {

            $provider = is_string($config['provider'] ?? null) ? $config['provider'] : null;
            $guard    = new RequestGuard(static fn (): null => null, $app->make('request'), Auth::createUserProvider($provider));

            $app->refresh('request', $guard, 'setRequest');

            return $guard;
        });

        Auth::viaRequest('early_request', static fn (): null => null);

        Auth::resolveUsersUsing(static fn (): GenericUser => new GenericUser(['id' => self::USER]));
    }

    /**
     * Resolve the default guard.
     *
     * @return void
     */
    public function boot(): void
    {
        $this->app->make('auth.driver');
    }
}
