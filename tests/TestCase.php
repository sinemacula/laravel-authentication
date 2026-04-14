<?php

declare(strict_types = 1);

namespace Tests;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as OrchestraTestCase;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
use SineMacula\Laravel\Authentication\Models\Device;

/**
 * Shared base test case for the package's integration tests.
 *
 * Boots a minimal Testbench application with the package service provider
 * registered, an in-memory sqlite connection, the package's default
 * `laravel-authentication` config block seeded, and the shipped `devices` table
 * created. Subclasses may override `defineEnvironment` to add per-test config
 * and `defineDatabaseMigrations` (or use `setUp`) to create additional tables.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
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
     * Seed the database connection and package config defaults.
     *
     * Reads `DB_CONNECTION` from the environment to select the driver.
     * Defaults to in-memory SQLite when unset, so local development needs
     * no extra configuration.
     *
     * @param  mixed  $app
     * @return void
     */
    protected function defineEnvironment(mixed $app): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', $this->databaseConnection());

        $config->set('authentication.device.model', Device::class);
        $config->set('authentication.device.table', 'devices');
        $config->set('authentication.device.refresh_key_column', 'refresh_key');
        $config->set('authentication.jwt.secret', 'test-secret-key-with-at-least-32-bytes!');
        $config->set('authentication.jwt.algorithm', 'HS256');
        $config->set('authentication.jwt.access_ttl_minutes', 15);
        $config->set('authentication.jwt.refresh_ttl_minutes', 60 * 24 * 30);
    }

    /**
     * Build the database connection config from environment variables.
     *
     * @return array<string, mixed>
     */
    private function databaseConnection(): array
    {
        $driver = env('DB_CONNECTION', 'sqlite');

        if ($driver === 'sqlite') {
            return [
                'driver'   => 'sqlite',
                'database' => ':memory:',
                'prefix'   => '',
            ];
        }

        return [
            'driver'   => $driver,
            'host'     => env('DB_HOST', '127.0.0.1'),
            'port'     => env('DB_PORT', $driver === 'pgsql' ? '5432' : '3306'),
            'database' => env('DB_DATABASE', 'laravel_authentication_test'),
            'username' => env('DB_USERNAME', 'root'),
            'password' => env('DB_PASSWORD', ''),
            'prefix'   => '',
            'charset'  => $driver === 'pgsql' ? 'utf8' : 'utf8mb4',
            'collation' => $driver === 'pgsql' ? null : 'utf8mb4_unicode_ci',
        ];
    }

    /**
     * Run the package's shipped devices migration so the default `devices`
     * table exists for tests that bind devices via the shipped `Device`
     * Eloquent model.
     *
     * With persistent databases (MySQL, PostgreSQL) the table survives
     * between test classes, so it must be dropped on teardown to prevent
     * the migration collision guard from throwing on the next class.
     *
     * @return void
     */
    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        if (env('DB_CONNECTION', 'sqlite') !== 'sqlite') {
            $this->beforeApplicationDestroyed(function (): void {
                Schema::dropIfExists(
                    app(ConfigRepository::class)->string('authentication.device.table', 'devices')
                );
            });
        }
    }
}
