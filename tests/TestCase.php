<?php

declare(strict_types = 1);

namespace Tests;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as OrchestraTestCase;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
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
    #[\Override]
    protected function getPackageProviders(mixed $app): array
    {
        return [
            AuthenticationServiceProvider::class,
        ];
    }

    /**
     * Seed the database connection and package config defaults.
     *
     * Reads `DB_CONNECTION` from the environment to select the driver. Defaults
     * to in-memory SQLite when unset, so local development needs no extra
     * configuration.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('database.default', 'testing');
        $config->set('database.connections.testing', $this->databaseConnection());

        $config->set('authentication.device.model', Device::class);
        $config->set('authentication.device.table', 'devices');
        $config->set('authentication.jwt.keys', ['test-kid' => 'test-secret-key-with-at-least-32-bytes!']);
        $config->set('authentication.jwt.active_kid', 'test-kid');
        $config->set('authentication.jwt.algorithm', 'HS256');
        $config->set('authentication.jwt.issuer', null);
        $config->set('authentication.jwt.audience', null);
        $config->set('authentication.jwt.access_ttl_minutes', 15);
        $config->set('authentication.jwt.refresh_idle_ttl_minutes', 60 * 24 * 30);
    }

    /**
     * Run the package's shipped migrations so the default `devices` and
     * `rate_limits` tables exist for tests that use the shipped models.
     *
     * With persistent databases (MySQL, PostgreSQL) the tables survive between
     * test classes, so they must be dropped on teardown to prevent the
     * migration collision guard, or a duplicate table, from failing the next
     * class.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');

        if ((getenv('DB_CONNECTION') ?: 'sqlite') === 'sqlite') {
            return;
        }

        $this->beforeApplicationDestroyed(function (): void {
            $config = app(ConfigRepository::class);

            Schema::dropIfExists($config->string('authentication.device.table', 'devices'));
            Schema::dropIfExists($config->string('authentication.rate_limits.table', 'rate_limits'));
        });
    }

    /**
     * Build the database connection config from environment variables.
     *
     * @return array<string, mixed>
     */
    private function databaseConnection(): array
    {
        $driver = getenv('DB_CONNECTION') ?: 'sqlite';

        if ($driver === 'sqlite') {
            return [
                'driver'   => 'sqlite',
                'database' => ':memory:',
                'prefix'   => '',
            ];
        }

        return [
            'driver'    => $driver,
            'host'      => getenv('DB_HOST') ?: '127.0.0.1',
            'port'      => getenv('DB_PORT') ?: $this->defaultPort($driver),
            'database'  => getenv('DB_DATABASE') ?: 'laravel_authentication_test',
            'username'  => getenv('DB_USERNAME') ?: 'root',
            'password'  => getenv('DB_PASSWORD') ?: '',
            'prefix'    => '',
            'charset'   => $driver === 'pgsql' ? 'utf8' : 'utf8mb4',
            'collation' => $driver === 'pgsql' ? null : 'utf8mb4_unicode_ci',
        ];
    }

    /**
     * Return the default database port for the given driver.
     *
     * @param  string  $driver
     * @return string
     */
    private function defaultPort(string $driver): string
    {
        return $driver === 'pgsql' ? '5432' : '3306';
    }
}
