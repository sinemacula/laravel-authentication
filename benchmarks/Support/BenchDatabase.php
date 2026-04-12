<?php

declare(strict_types = 1);

namespace Benchmarks\Support;

use Illuminate\Database\Capsule\Manager as Capsule;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Schema\Builder as SchemaBuilder;

/**
 * Shared sqlite in-memory database for PHPBench auth-path
 * fixtures.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Ltd
 */
final class BenchDatabase
{
    /** @var ?\Illuminate\Database\Capsule\Manager Shared database capsule. */
    private static ?Capsule $capsule = null;

    /**
     * Bootstrap Eloquent once for the benchmark process.
     *
     * @return void
     */
    public static function boot(): void
    {
        if (self::$capsule !== null) {
            return;
        }

        $capsule = new Capsule;
        $capsule->addConnection([
            'driver'   => 'sqlite',
            'database' => ':memory:',
            'prefix'   => '',
        ]);
        $capsule->setAsGlobal();
        $capsule->bootEloquent();

        self::$capsule = $capsule;
    }

    /**
     * Return the shared schema builder.
     *
     * @return \Illuminate\Database\Schema\Builder
     */
    public static function schema(): SchemaBuilder
    {
        return self::capsule()->getConnection()->getSchemaBuilder();
    }

    /**
     * Return the shared connection resolver used by refresh exchanges.
     *
     * @return \Illuminate\Database\ConnectionResolverInterface
     */
    public static function connectionResolver(): ConnectionResolverInterface
    {
        return self::capsule()->getDatabaseManager();
    }

    /**
     * Return the booted database capsule.
     *
     * @return \Illuminate\Database\Capsule\Manager
     */
    private static function capsule(): Capsule
    {
        self::boot();

        if (self::$capsule === null) {
            throw new \LogicException('Benchmark database capsule was not initialized.');
        }

        return self::$capsule;
    }
}
