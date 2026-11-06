<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Support;

use Illuminate\Database\Eloquent\Model;

/**
 * What tells an Eloquent model's row apart from every other within one request
 * or job: its connection, that connection's database, its table (with the
 * connection's prefix) and its key, so the same key in another database or
 * table is another row.
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
