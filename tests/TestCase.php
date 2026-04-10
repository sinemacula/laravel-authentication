<?php

declare(strict_types = 1);

namespace Tests;

use Illuminate\Config\Repository as ConfigRepository;
use Orchestra\Testbench\TestCase as OrchestraTestCase;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * Shared base test case for the package's integration tests.
 *
 * Boots a minimal Testbench application with the package service provider
 * registered, an in-memory sqlite connection, the package's default
 * `laravel-authentication` config block seeded, and the shipped `devices`
 * table created. Subclasses may override `defineEnvironment` to add per-test
 * config and `defineDatabaseMigrations` (or use `setUp`) to create additional
 * tables.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
abstract class TestCase extends OrchestraTestCase
{
    /**
     * Register the package service provider.
     *
     * @param  mixed  $app
     * @return array<int, class-string<\Illuminate\Support\ServiceProvider>>
     */
    protected function getPackageProviders(mixed $app): array
    {
        return [
            AuthServiceProvider::class,
        ];
    }

    /**
     * Seed the in-memory sqlite connection and package config defaults.
     *
     * @param  mixed  $app
     * @return void
     */
    protected function defineEnvironment(mixed $app): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', [
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);

        $config->set('authentication.device.model', Device::class);
        $config->set('authentication.device.table', 'devices');
        $config->set('authentication.device.refresh_key_column', 'refresh_key');
        $config->set('authentication.jwt.secret', 'test-secret-key-with-at-least-32-bytes!');
        $config->set('authentication.jwt.algorithm', 'HS256');
        $config->set('authentication.jwt.access_ttl_minutes', 15);
        $config->set('authentication.jwt.refresh_ttl_minutes', 60 * 24 * 30);
    }

    /**
     * Run the package's shipped devices migration so the default `devices`
     * table exists for tests that bind devices via the shipped `Device`
     * Eloquent model.
     *
     * @return void
     */
    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
    }
}
