<?php

declare(strict_types = 1);

namespace Tests\Unit\Database;

use Illuminate\Database\SQLiteConnection;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Database\GrammarExpression;

/**
 * Unit tests for the SQL fragment a grammar compiles.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GrammarExpression::class)]
final class GrammarExpressionTest extends TestCase
{
    /**
     * Identifiers are wrapped and values escaped, identifiers first.
     *
     * @return void
     */
    public function testWrapsIdentifiersThenEscapesValues(): void
    {
        $grammar = (new SQLiteConnection(new \PDO('sqlite::memory:')))->getQueryGrammar();

        $expression = new GrammarExpression('%1$s > %3$s or %2$s = %4$s', ['expires_at', 'users.name'], ['2026-01-01', 'o\'brien']);

        self::assertSame('"expires_at" > \'2026-01-01\' or "users"."name" = \'o\'\'brien\'', $expression->getValue($grammar));
    }
}
