<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Database;

/**
 * Runs the package's shipped migrations, requiring each file once per process:
 * every require declares a new anonymous class.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ShippedMigrations
{
    /** @var string The directory the shipped migrations are in. */
    private const string DIRECTORY = __DIR__ . '/../../../database/migrations/';

    /** @var array<string, mixed> The migrations required so far, by file name. */
    private static array $required = [];

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Run the shipped migration in the file.
     *
     * @param  string  $file
     * @return void
     *
     * @throws \LogicException
     */
    public static function up(string $file): void
    {
        $migration = self::migration($file);

        if (!method_exists($migration, 'up')) {
            throw new \LogicException(sprintf('%s cannot be run.', $file));
        }

        $migration->up();
    }

    /**
     * Reverse the shipped migration in the file.
     *
     * @param  string  $file
     * @return void
     *
     * @throws \LogicException
     */
    public static function down(string $file): void
    {
        $migration = self::migration($file);

        if (!method_exists($migration, 'down')) {
            throw new \LogicException(sprintf('%s cannot be reversed.', $file));
        }

        $migration->down();
    }

    /**
     * The shipped migration in the file, required the first time it is asked
     * for.
     *
     * @param  string  $file
     * @return object
     *
     * @throws \LogicException
     */
    private static function migration(string $file): object
    {
        $migration = self::$required[$file] ??= require self::DIRECTORY . $file;

        if (!is_object($migration)) {
            throw new \LogicException(sprintf('%s does not return a migration.', $file));
        }

        return $migration;
    }
}
