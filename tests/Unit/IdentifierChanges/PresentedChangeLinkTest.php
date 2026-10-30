<?php

declare(strict_types = 1);

namespace Tests\Unit\IdentifierChanges;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\IdentifierChanges\PresentedChangeLink;

/**
 * Unit tests for reading a change link's fields from a request's query: each
 * must be a string, and the type a valid identifier type.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PresentedChangeLink::class)]
final class PresentedChangeLinkTest extends TestCase
{
    /** @var array<string, string> A complete set of fields. */
    private const array FIELDS = ['guard' => 'web', 'identity' => '7', 'type' => 'email', 'request' => 'request-1', 'hash' => 'digest'];

    /**
     * Every field is read as given.
     *
     * @return void
     */
    public function testReadsEveryField(): void
    {
        $link = PresentedChangeLink::of(Request::create('/confirm', 'GET', self::FIELDS));

        self::assertNotNull($link);
        self::assertSame(['web', '7', 'email', 'request-1', 'digest'], [$link->guard, $link->identity, $link->type, $link->requestId, $link->hash]);
    }

    /**
     * Rows of `[field, value]`: each field missing or given as a list, and a
     * malformed type.
     *
     * @return iterable<string, array{0: string, 1: mixed}>
     */
    public static function provideMalformedFields(): iterable
    {
        foreach (array_keys(self::FIELDS) as $field) {
            yield "{$field} missing" => [$field, null];
            yield "{$field} a list" => [$field, ['a', 'b']];
        }

        yield 'a malformed type' => ['type', 'Email'];
    }

    /**
     * A query without every field as a string, or with a malformed type, is no
     * change link.
     *
     * @param  string  $field
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMalformedFields')]
    public function testAMissingOrMalformedFieldIsNoLink(string $field, mixed $value): void
    {
        $query = self::FIELDS;

        if ($value === null) {
            unset($query[$field]);
        } else {
            $query[$field] = $value;
        }

        self::assertNull(PresentedChangeLink::of(Request::create('/confirm', 'GET', $query)));
    }
}
