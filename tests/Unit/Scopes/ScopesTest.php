<?php

declare(strict_types = 1);

namespace Tests\Unit\Scopes;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException;
use SineMacula\Laravel\Authentication\Scopes\AcceptAnyScope;
use SineMacula\Laravel\Authentication\Scopes\Scopes;
use Tests\Unit\Stubs\PlainPrincipalFixture;

/**
 * Unit tests for the scope convention: the RFC 6749 scope-token syntax, the
 * stored list form, the space-separated string form, subsets, and the scope
 * registry a credential's scopes are held to.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Scopes::class)]
#[CoversClass(AcceptAnyScope::class)]
#[CoversClass(InvalidScopeException::class)]
final class ScopesTest extends TestCase
{
    /**
     * Scopes keep their first order with duplicates removed, as opaque strings:
     * case, punctuation and namespacing are the application's.
     *
     * @return void
     */
    public function testNormaliseKeepsOrderAndRemovesDuplicates(): void
    {
        self::assertSame(
            ['invoices:read', 'Invoices:Read', 'https://api.example.test/reports', 'a'],
            Scopes::normalise(['invoices:read', 'Invoices:Read', 'invoices:read', 'https://api.example.test/reports', 'a', 'a']),
        );

        self::assertSame(['b', 'a'], Scopes::normalise([5 => 'b', 'x' => 'a']));
        self::assertSame([], Scopes::normalise([]));
    }

    /**
     * The edges of a scope token: every printable ASCII character but space,
     * `"` and `\`, and at most 255 bytes.
     *
     * @return void
     */
    public function testAcceptsEveryScopeTokenCharacterUpToTheLimit(): void
    {
        $characters = implode('', array_map('chr', [0x21, ...range(0x23, 0x5B), ...range(0x5D, 0x7E)]));

        self::assertSame([$characters], Scopes::normalise([$characters]));
        self::assertSame([str_repeat('a', 255)], Scopes::normalise([str_repeat('a', 255)]));
    }

    /**
     * A list of scopes is accepted up to 8,192 bytes written space-separated,
     * duplicates not counted; one byte more refuses the scopes from the first
     * that does not fit.
     *
     * @return void
     */
    public function testBoundsTheListOfScopes(): void
    {
        $scopes = self::longestScopes();

        self::assertSame(Scopes::MAX_LIST_LENGTH, strlen(Scopes::format($scopes)));
        self::assertSame($scopes, Scopes::normalise([...$scopes, $scopes[0]]));

        try {
            Scopes::normalise([...$scopes, 'x']);

            self::fail('Expected the list to be refused.');
        } catch (InvalidScopeException $exception) {
            self::assertSame(['x'], $exception->scopes);
            self::assertSame('The scopes, written space-separated, must be at most 8192 bytes.', $exception->getMessage());
        }

        try {
            Scopes::normalise([...array_slice($scopes, 0, -1), end($scopes) . '/']);

            self::fail('Expected a list one byte too long to be refused.');
        } catch (InvalidScopeException $exception) {
            self::assertSame([end($scopes) . '/'], $exception->scopes);
        }

        try {
            Scopes::normalise(['x', ...$scopes]);

            self::fail('Expected the list to be refused.');
        } catch (InvalidScopeException $exception) {
            self::assertSame([end($scopes)], $exception->scopes);
        }
    }

    /**
     * Rows of `[scope, reported]`: values that are not scope tokens, and how
     * the exception names each.
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function provideMalformedScopes(): iterable
    {
        yield from [
            'empty'          => ['', ''],
            'space'          => ['a b', 'a b'],
            'leading space'  => [' a', ' a'],
            'double quote'   => ['a"b', 'a"b'],
            'backslash'      => ['a\b', 'a\b'],
            'control'        => ["a\tb", "a\tb"],
            'newline at end' => ["a\n", "a\n"],
            'delete'         => ["a\x7F", "a\x7F"],
            'non-ascii'      => ['café', 'café'],
            'too long'       => [str_repeat('a', 256), str_repeat('a', 256)],
            'integer'        => [5, 'int'],
            'null'           => [null, 'null'],
            'nested list'    => [['a'], 'array'],
        ];
    }

    /**
     * A value that is not a scope token is refused with the offending ones,
     * however many well-formed ones surround it.
     *
     * @param  mixed  $scope
     * @param  string  $reported
     * @return void
     */
    #[DataProvider('provideMalformedScopes')]
    public function testNormaliseRefusesAMalformedScope(mixed $scope, string $reported): void
    {
        try {
            Scopes::normalise(['ok', $scope, 'fine']);

            self::fail('Expected the scope to be refused.');
        } catch (InvalidScopeException $exception) {
            self::assertSame([$reported], $exception->scopes);
            self::assertSame('Each scope must be an RFC 6749 scope token (printable ASCII other than space, `"` and `\`) of at most 255 bytes.', $exception->getMessage());
            self::assertInstanceOf(\InvalidArgumentException::class, $exception);
        }
    }

    /**
     * Every malformed scope is reported, not just the first.
     *
     * @return void
     */
    public function testNormaliseReportsEveryMalformedScope(): void
    {
        try {
            Scopes::normalise(['a b', 'ok', '', 7]);

            self::fail('Expected the scopes to be refused.');
        } catch (InvalidScopeException $exception) {
            self::assertSame(['a b', '', 'int'], $exception->scopes);
        }
    }

    /**
     * A scope string is tokens separated by single spaces; the empty string
     * names none.
     *
     * @return void
     */
    public function testParseReadsASpaceSeparatedString(): void
    {
        self::assertSame([], Scopes::parse(''));
        self::assertSame(['a'], Scopes::parse('a'));
        self::assertSame(['invoices:read', 'invoices:write'], Scopes::parse('invoices:read invoices:write invoices:read'));
    }

    /**
     * Rows of `[scope]`: scope strings RFC 6749 section 3.3 does not allow.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMalformedScopeStrings(): iterable
    {
        yield from [
            'double space'   => ['a  b'],
            'leading space'  => [' a'],
            'trailing space' => ['a '],
            'only a space'   => [' '],
            'tab separated'  => ["a\tb"],
            'quoted'         => ['"a"'],
        ];
    }

    /**
     * A malformed scope string is refused.
     *
     * @param  string  $scope
     * @return void
     */
    #[DataProvider('provideMalformedScopeStrings')]
    public function testParseRefusesAMalformedString(string $scope): void
    {
        $this->expectException(InvalidScopeException::class);

        Scopes::parse($scope);
    }

    /**
     * Scopes are written with single spaces, and an empty list as the empty
     * string; parsing what was written gives the list back.
     *
     * @return void
     */
    public function testFormatWritesASpaceSeparatedString(): void
    {
        self::assertSame('', Scopes::format([]));
        self::assertSame('invoices:read invoices:write', Scopes::format(['invoices:read', 'invoices:write']));
        self::assertSame(['invoices:read', 'invoices:write'], Scopes::parse(Scopes::format(['invoices:read', 'invoices:write'])));
    }

    /**
     * A request is a subset when every scope it names is granted; no scope at
     * all is a subset of anything.
     *
     * @return void
     */
    public function testIsSubset(): void
    {
        self::assertTrue(Scopes::isSubset([], []));
        self::assertTrue(Scopes::isSubset([], ['a']));
        self::assertTrue(Scopes::isSubset(['b', 'a'], ['a', 'b', 'c']));
        self::assertFalse(Scopes::isSubset(['a'], []));
        self::assertFalse(Scopes::isSubset(['a', 'd'], ['a', 'b']));
        self::assertFalse(Scopes::isSubset(['A'], ['a']));
    }

    /**
     * The default registry rejects nothing, so every well-formed scope is
     * grantable, normalised.
     *
     * @return void
     */
    public function testTheDefaultRegistryAcceptsEveryScope(): void
    {
        $registry  = new AcceptAnyScope;
        $principal = new PlainPrincipalFixture('p-1');

        self::assertSame([], $registry->rejected('machine', $principal, ['anything', 'at:all']));
        self::assertSame(['a', 'b'], Scopes::grantable($registry, 'machine', $principal, ['a', 'b', 'a']));
    }

    /**
     * Rows of `[scopes asked for, the registry's answer, scopes refused]`.
     *
     * @return iterable<string, array{0: list<string>, 1: list<string>, 2: list<string>}>
     */
    public static function provideRegistryRefusals(): iterable
    {
        yield from [
            'a scope it rejects'              => [['read', 'admin'], ['admin'], ['admin']],
            'scopes named in its own order'   => [['admin', 'read', 'write'], ['write', 'admin'], ['admin', 'write']],
            'a given scope and one not asked' => [['read', 'admin'], ['not-asked', 'admin'], ['admin']],
            'only a scope not asked about'    => [['read'], ['not-asked'], ['read']],
            'a pattern'                       => [['read', 'admin:users'], ['admin:*'], ['read', 'admin:users']],
            'a scope in a form of its own'    => [['admin'], ['Admin'], ['admin']],
            'everything'                      => [['read', 'write'], ['*'], ['read', 'write']],
        ];
    }

    /**
     * The registry is asked about the normalised scopes for the guard and the
     * principal, and any answer but `[]` refuses them: the given scopes it
     * names are named, or every given scope when it names none of them as
     * given.
     *
     * @param  list<string>  $scopes
     * @param  list<string>  $answer
     * @param  list<string>  $refused
     * @return void
     */
    #[DataProvider('provideRegistryRefusals')]
    public function testARegistryRejectionIsRefused(array $scopes, array $answer, array $refused): void
    {
        $principal = new PlainPrincipalFixture('p-1');
        $registry  = new class ($answer) implements ScopeRegistry {
            /** @var list<array{0: string, 1: \SineMacula\Laravel\Authentication\Contracts\Principal, 2: list<string>}> What the registry was asked. */
            public array $asked = [];

            /**
             * Constructor.
             *
             * @param  list<string>  $answer
             */
            public function __construct(

                /** What the registry answers. */
                private readonly array $answer,
            ) {}

            /**
             * Give the answer.
             *
             * @param  string  $guard
             * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
             * @param  list<string>  $scopes
             * @return list<string>
             */
            #[\Override]
            public function rejected(string $guard, Principal $principal, array $scopes): array
            {
                $this->asked[] = [$guard, $principal, $scopes];

                return $this->answer;
            }
        };

        try {
            Scopes::grantable($registry, 'machine', $principal, [...$scopes, $scopes[0]]);

            self::fail('Expected the registry to refuse the scopes.');
        } catch (InvalidScopeException $exception) {
            self::assertSame($refused, $exception->scopes);
            self::assertSame('The scope registry does not allow these scopes for the principal on guard [machine].', $exception->getMessage());
        }

        self::assertSame([['machine', $principal, $scopes]], $registry->asked);
    }

    /**
     * A malformed scope is refused before the registry is asked.
     *
     * @return void
     */
    public function testAMalformedScopeIsRefusedBeforeTheRegistryIsAsked(): void
    {
        $registry = $this->createMock(ScopeRegistry::class);
        $registry->expects(self::never())->method('rejected');

        $this->expectException(InvalidScopeException::class);

        Scopes::grantable($registry, 'machine', new PlainPrincipalFixture('p-1'), ['a b']);
    }

    /**
     * Distinct scopes that, written space-separated, take exactly the most
     * bytes a list may: 31 of 255 bytes, one of 128 and one of 127, mostly
     * slashes, which JSON escapes, so the stored form is as long as it gets.
     *
     * @return list<string>
     */
    private static function longestScopes(): array
    {
        $scopes = [];

        for ($index = 0; $index < 31; $index++) {
            $scopes[] = sprintf('%04d', $index) . str_repeat('/', 251);
        }

        return [...$scopes, 'a' . str_repeat('/', 127), 'b' . str_repeat('/', 126)];
    }
}
