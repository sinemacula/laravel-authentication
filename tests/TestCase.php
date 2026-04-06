<?php

declare(strict_types=1);

namespace Tests;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Orchestra\Testbench\TestCase as OrchestraTestCase;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * Shared base test case for the package's integration tests.
 *
 * Boots a minimal Testbench application with the package service
 * provider registered, an in-memory sqlite connection, the package's
 * default `laravel-authentication` config block seeded, and the
 * shipped `devices` table created. Subclasses may override
 * `defineEnvironment` to add per-test config and `defineDatabaseMigrations`
 * (or use `setUp`) to create additional tables.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @internal
 */
abstract class TestCase extends OrchestraTestCase
{
    /**
     * Register the package service provider with the Testbench app.
     *
     * @param  Application $app The Testbench application under construction.
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            AuthServiceProvider::class,
        ];
    }

    /**
     * Seed the in-memory sqlite connection and the package's default
     * `laravel-authentication` config block.
     *
     * Subclasses that need extra config (e.g. additional guards or
     * providers) should override `defineEnvironment` and call
     * `parent::defineEnvironment($app)` first.
     *
     * @param  Application $app The Testbench application under construction.
     * @return void
     */
    protected function defineEnvironment($app): void
    {
        /** @var ConfigRepository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);

        $config->set('laravel-authentication.device.model', Device::class);
        $config->set('laravel-authentication.device.table', 'devices');
        $config->set('laravel-authentication.device.refresh_key_column', 'refresh_key');
        $config->set('laravel-authentication.scopes.internal', 'internal');
        $config->set('laravel-authentication.scopes.external', 'external');
        $config->set('laravel-authentication.jwt.secret', 'test-secret-key-with-at-least-32-bytes!');
        $config->set('laravel-authentication.jwt.algorithm', 'HS256');
        $config->set('laravel-authentication.jwt.access_ttl_minutes', 15);
        $config->set('laravel-authentication.jwt.refresh_ttl_minutes', 60 * 24 * 30);
    }

    /**
     * Run the package's shipped devices migration so the default
     * `devices` table exists for tests that bind devices via the
     * shipped `Device` Eloquent model.
     *
     * Tests that need a different table layout (e.g. T25's device
     * model override test) should either skip this hook by overriding
     * `defineDatabaseMigrations` or drop and re-create the table in
     * their own setUp.
     *
     * @return void
     */
    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
    }
}
