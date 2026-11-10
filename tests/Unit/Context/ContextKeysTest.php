<?php

declare(strict_types = 1);

namespace Tests\Unit\Context;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Context\ContextKeys;
use SineMacula\Laravel\Authentication\Context\Enums\CredentialKind;

/**
 * Unit tests for the rules an authentication context's namespaces and
 * contributed keys keep: a namespace in its form and not the package's own, a
 * key in its form, a value `null`, a scalar or an array of them, and the first
 * key that breaks a rule named in what is wrong.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContextKeys::class)]
final class ContextKeysTest extends TestCase
{
    /** @var string What the refusal of a key out of form says after naming it. */
    private const string KEY_RULE = 'must be a lower-case letter and then up to 63 lower-case letters, digits or underscores.';

    /** @var string What the refusal of a value that is not plain says after naming it. */
    private const string VALUE_RULE = 'must be null, a scalar or an array of them, never an object or a resource.';

    /**
     * Rows of `[name, whether it is a namespace]`: names in the form, at the
     * shortest and the longest, and names that are not, the package's own
     * included.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideNamespaces(): iterable
    {
        yield 'a short name' => ['sso', true];
        yield 'one letter' => ['a', true];
        yield 'letters, digits and underscores' => ['mfa_2', true];
        yield 'the longest' => ['a' . str_repeat('b', 31), true];
        yield 'the package\'s own' => ['authentication', false];
        yield 'empty' => ['', false];
        yield 'upper case' => ['Sso', false];
        yield 'a leading digit' => ['1sso', false];
        yield 'a leading underscore' => ['_sso', false];
        yield 'a dot' => ['sso.keys', false];
        yield 'a hyphen' => ['single-sign-on', false];
        yield 'a trailing newline' => ["sso\n", false];
        yield 'too long' => ['a' . str_repeat('b', 32), false];
    }

    /**
     * A namespace is a lower-case letter and then up to 31 lower-case letters,
     * digits or underscores, and never the package's own.
     *
     * @param  string  $name
     * @param  bool  $expected
     * @return void
     */
    #[DataProvider('provideNamespaces')]
    public function testANamespaceIsInItsFormAndNotThePackagesOwn(string $name, bool $expected): void
    {
        self::assertSame($expected, ContextKeys::isNamespace($name));
    }

    /**
     * Keys in their form holding plain values are taken as given, in the order
     * given: the shortest and the longest names, `null`, every scalar, and
     * arrays of them nested, an empty one included.
     *
     * @return void
     */
    public function testPlainKeysAreTakenAsGiven(): void
    {
        $longest = 'k' . str_repeat('e', 63);
        $keys    = [
            'a'      => null,
            'flag'   => false,
            'count'  => 3,
            'ratio'  => 0.5,
            'name'   => 'connection-7',
            'nested' => ['list' => [1, 'two', null, [true]], 'empty' => []],
            'link_2' => 'link-9',
            $longest => 'longest',
        ];

        self::assertSame($keys, ContextKeys::checked('sso', $keys));
        self::assertSame([], ContextKeys::checked('sso', []));
    }

    /**
     * Rows of `[keys, what is wrong]`: keys no contributor may give, and the
     * first problem named.
     *
     * @return iterable<string, array{0: mixed, 1: string}>
     */
    public static function provideRefusedKeys(): iterable
    {
        $object = new \stdClass;

        yield 'not an array' => ['connection-7', 'The keys contributed under [sso] must be an array.'];
        yield 'null' => [null, 'The keys contributed under [sso] must be an array.'];
        yield 'a key that is a number' => [['connection-7'], 'The key [0] contributed under [sso] ' . self::KEY_RULE];
        yield 'a key in upper case' => [['Id' => 'a'], 'The key [Id] contributed under [sso] ' . self::KEY_RULE];
        yield 'a key with a leading digit' => [['1id' => 'a'], 'The key [1id] contributed under [sso] must be'];
        yield 'a key with a leading underscore' => [['_id' => 'a'], 'The key [_id] contributed under [sso] must be'];
        yield 'a key with a dot' => [['connection.id' => 'a'], 'The key [connection.id] contributed under [sso] must be'];
        yield 'a key with a trailing newline' => [["id\n" => 'a'], "The key [id\n] contributed under [sso] must be"];
        yield 'an empty key' => [['' => 'a'], 'The key [] contributed under [sso] must be'];
        yield 'a key too long' => [['k' . str_repeat('e', 64) => 'a'], 'The key [k' . str_repeat('e', 64) . '] contributed under [sso] must be'];
        yield 'an object' => [['link' => $object], 'The value of [sso.link] ' . self::VALUE_RULE];
        yield 'an object nested' => [['links' => ['a', ['b' => $object]]], 'The value of [sso.links] ' . self::VALUE_RULE];
        yield 'an enum' => [['kind' => CredentialKind::API_KEY], 'The value of [sso.kind] must be null'];
        yield 'the first of two problems' => [['ok' => 1, 'Bad' => 2, 'worse' => $object], 'The key [Bad] contributed under [sso]'];
    }

    /**
     * Keys no contributor may give are answered with what is wrong with the
     * first, naming the namespace and the key.
     *
     * @param  mixed  $keys
     * @param  non-empty-string  $problem
     * @return void
     */
    #[DataProvider('provideRefusedKeys')]
    public function testKeysNoContributorMayGiveAreAnsweredWithTheFirstProblem(mixed $keys, string $problem): void
    {
        $checked = ContextKeys::checked('sso', $keys);

        self::assertIsString($checked);
        self::assertStringStartsWith($problem, $checked);
    }

    /**
     * A resource is no plain value, at the top or nested.
     *
     * @return void
     */
    public function testAResourceIsNoPlainValue(): void
    {
        $resource = fopen('php://memory', 'rb');

        try {
            self::assertSame('The value of [sso.stream] ' . self::VALUE_RULE, ContextKeys::checked('sso', ['stream' => $resource]));
            self::assertSame('The value of [sso.streams] ' . self::VALUE_RULE, ContextKeys::checked('sso', ['streams' => [[$resource]]]));
        } finally {
            fclose($resource);
        }
    }
}
