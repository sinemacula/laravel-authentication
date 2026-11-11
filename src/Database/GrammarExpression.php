<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

use Illuminate\Contracts\Database\Query\Expression;
use Illuminate\Database\Grammar;

/**
 * A literal SQL fragment whose identifiers and values the compiling grammar
 * wraps and escapes into its `sprintf()` placeholders.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GrammarExpression implements Expression
{
    /**
     * Create a new grammar expression.
     *
     * @param  literal-string  $sql
     * @param  list<string>  $identifiers
     * @param  list<string>  $values
     */
    public function __construct(

        /** The fragment, a `sprintf()` format. */
        private string $sql,

        /** The identifiers the grammar wraps into it. */
        private array $identifiers = [],

        /** The values the grammar escapes into it, after the identifiers. */
        private array $values = [],
    ) {}

    /**
     * Return the fragment with its identifiers wrapped and its values escaped
     * by the grammar given.
     *
     * @param  \Illuminate\Database\Grammar  $grammar
     * @return string
     */
    #[\Override]
    public function getValue(Grammar $grammar): string
    {
        return vsprintf($this->sql, [
            ...array_map($grammar->wrap(...), $this->identifiers),
            ...array_map(static fn (string $value): string => $grammar->escape($value), $this->values),
        ]);
    }
}
