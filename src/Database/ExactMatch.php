<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

use Illuminate\Contracts\Database\Query\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Query\Grammars\MySqlGrammar;
use Illuminate\Database\Query\Grammars\PostgresGrammar;
use Illuminate\Database\Query\Grammars\SqlServerGrammar;

/**
 * Hold a query to rows whose columns equal the values byte for byte, whatever
 * the columns' collation counts as equal.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ExactMatch
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Hold the query of the model's rows to those whose columns equal the
     * values byte for byte; a `null` value matches no row.
     *
     * @template TBuilder of \Illuminate\Contracts\Database\Query\Builder
     *
     * @param  TBuilder  $query
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  array<string, ?string>  $values
     * @return TBuilder
     */
    public static function where(Builder $query, Model $model, array $values): Builder
    {
        // MySQL compares utf8mb4 bytes whatever the column's charset, citext
        // and non-text columns take no collation, and SQL Server's `=` pads.
        $grammar = $model->getConnection()->getQueryGrammar();

        $format = match (true) {
            $grammar instanceof MySqlGrammar     => 'cast(convert(%s using utf8mb4) as binary) = ?',
            $grammar instanceof PostgresGrammar  => 'cast(%s as text) collate "C" = ?',
            $grammar instanceof SqlServerGrammar => 'concat(%s, \'.\') collate Latin1_General_BIN2 = concat(?, \'.\')',
            default                              => '%s collate binary = ?',
        };

        foreach ($values as $column => $value) {

            // SQL Server's concat() reads null as an empty string.
            if ($value === null) {
                $query->whereRaw('0 = 1');
                continue;
            }

            $column = $model->qualifyColumn($column);

            // The collation's own comparison keeps the column's index in use.
            $query->where($column, $value)->whereRaw(new GrammarExpression($format, [$column]), [$value]);
        }

        return $query;
    }
}
