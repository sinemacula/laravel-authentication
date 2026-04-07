<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

use Illuminate\Database\Schema\Builder;

/**
 * Migration collision guard.
 *
 * Helper consumed by the shipped devices migration. Surfaces a clear,
 * actionable error before any schema mutation if the configured devices
 * table already exists in the consumer's schema (REQ-13/AC-13).
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
final class MigrationCollisionGuard
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\Schema\Builder  $schema
     */
    public function __construct(

        /** Schema builder used to inspect the active connection. */
        protected Builder $schema,

    ) {}

    /**
     * Throw if the configured devices table already exists.
     *
     * @param  string  $table
     * @return void
     *
     * @throws \SineMacula\Laravel\Authentication\Database\DeviceTableAlreadyExistsException
     */
    public function ensureNotExists(string $table): void
    {
        if (!$this->schema->hasTable($table)) {
            return;
        }

        $connection = $this->schema->getConnection()->getName() ?? 'default';

        $message = sprintf(
            'Cannot install the laravel-authentication devices migration: a table named \'%s\' already exists on connection \'%s\'.'
            . ' Set `device.table` in config/laravel-authentication.php to a different name and re-run the migration.',
            $table,
            $connection,
        );

        throw new DeviceTableAlreadyExistsException($message);
    }
}
