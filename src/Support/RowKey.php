<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Support;

use Illuminate\Database\Eloquent\Model;

/**
 * Identifies a model's row by connection, database, prefixed table and key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RowKey
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The key of the model's row.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return string
     */
    public static function of(Model $model): string
    {
        $connection = $model->getConnection();

        return implode("\0", [
            'row',
            $connection->getName(),
            $connection->getDatabaseName(),
            $connection->getTablePrefix() . $model->getTable(),
            IdentifierCoercion::stringify($model->getKey()),
        ]);
    }
}
