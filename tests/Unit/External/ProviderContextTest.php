<?php

declare(strict_types = 1);

namespace Tests\Unit\External;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\External\ProviderContext;

/**
 * Unit tests for the provider context an adapter gives with its result: the
 * values it keeps, by value, the shapes and sizes it refuses, and the stored
 * form it encodes and reads back, where anything malformed is no context at
 * all.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProviderContext::class)]
final class ProviderContextTest extends TestCase
{
    /** @var string The message a value of a type JSON does not keep is refused with. */
    private const string TYPE = 'A provider context\'s values must be null, booleans, numbers, strings or arrays of them.';

    /** @var string The message a value nested too deep is refused with. */
    private const string DEPTH = 'A provider context may nest arrays at most 4 deep.';

    /** @var string The message a context whose stored form does not fit is refused with. */
    private const string STORED = 'A provider context must be valid UTF-8, hold only finite numbers and take at most 4096 bytes as stored.';

    /**
     * A context keeps every value JSON keeps as it was given, lists and maps
     * nested to the deepest level allowed included, and stores them as ASCII
     * JSON whose floats stay floats.
     *
     * @return void
     */
    public function testAContextKeepsWhatTheAdapterGave(): void
    {
        $values = [
            'protocol' => 'saml',
            'verified' => true,
            'explicit' => false,
            'none'     => null,
            'zero'     => 0,
            'largest'  => PHP_INT_MAX,
            'smallest' => PHP_INT_MIN,
            'whole'    => 1.0,
            'ratio'    => 0.25,
            'empty'    => '',
            'name'     => 'Zoë/ß',
            'list'     => ['a', 1, ['b' => [true]]],
            'map'      => [3 => 'x', 'y' => []],
        ];

        $context = new ProviderContext($values);

        self::assertSame($values, $context->values);
        self::assertSame($values, $context->toArray());
        self::assertSame([4096, 4], [ProviderContext::STORED_MAX_BYTES, ProviderContext::MAX_DEPTH]);
        self::assertSame(
            '{"protocol":"saml","verified":true,"explicit":false,"none":null,"zero":0,"largest":9223372036854775807,'
            . '"smallest":-9223372036854775808,"whole":1.0,"ratio":0.25,"empty":"","name":"Zo\u00eb\/\u00df",'
            . '"list":["a",1,{"b":[true]}],"map":{"3":"x","y":[]}}',
            $context->toStored(),
        );
    }

    /**
     * Arrays nest up to `MAX_DEPTH` deep, the map itself the first, and an
     * array nested one deeper is refused, empty or not, in a list or a map.
     *
     * @return void
     */
    public function testArraysNestNoDeeperThanAllowed(): void
    {
        self::assertSame(['a' => [[['x']]]], (new ProviderContext(['a' => [[['x']]]]))->toArray());
        self::assertSame(['a' => ['b' => ['c' => []]]], (new ProviderContext(['a' => ['b' => ['c' => []]]]))->toArray());

        foreach ([['a' => [[[['x']]]]], ['a' => ['b' => ['c' => ['d' => []]]]], ['a' => 1, 'b' => [[[[]]]]]] as $values) {
            try {
                new ProviderContext($values);

                self::fail('The context should have been refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(self::DEPTH, $exception->getMessage());
            }
        }
    }

    /**
     * Rows of `[values, message]` a context refuses, none of whose messages
     * repeats a value.
     *
     * @return iterable<string, array{0: array<array-key, mixed>, 1: string}>
     */
    public static function provideRefusedContexts(): iterable
    {
        $map  = 'A provider context must be a map with string keys.';
        $none = 'A provider context must hold at least one value; give none for no context.';

        yield from [
            'nothing'                  => [[], $none],
            'a list'                   => [['saml'], $map],
            'a key that is a number'   => [['protocol' => 'saml', 7 => 'x'], $map],
            'a key PHP makes a number' => [['12' => 'x'], $map],
            'an object'                => [['a' => new \stdClass], self::TYPE],
            'an enum'                  => [['a' => FailureReason::LINK_MISMATCH], self::TYPE],
            'a stringable object'      => [['a' => new class implements \Stringable {
                /**
                 * The text it stands for.
                 *
                 * @return string
                 */
                #[\Override]
                public function __toString(): string
                {
                    return 'secret';
                }
            }], self::TYPE],
            'a json serialisable object' => [['a' => new class implements \JsonSerializable {
                /**
                 * The value it encodes as.
                 *
                 * @return string
                 */
                #[\Override]
                public function jsonSerialize(): string
                {
                    return 'secret';
                }
            }], self::TYPE],
            'a closure'                      => [['a' => static fn (): string => 'secret'], self::TYPE],
            'a resource'                     => [['a' => fopen('php://memory', 'r')], self::TYPE],
            'a nested object'                => [['a' => ['b' => [new \stdClass]]], self::TYPE],
            'not a number'                   => [['a' => NAN], self::STORED],
            'infinity'                       => [['a' => ['b' => -INF]], self::STORED],
            'text that is not UTF-8'         => [['a' => "secret\xff"], self::STORED],
            'a nested key that is not UTF-8' => [['a' => ["\xff" => 1]], self::STORED],
            'a key that is not UTF-8'        => [["\xff" => 1], self::STORED],
        ];
    }

    /**
     * Anything but a non-empty map with string keys of values JSON keeps,
     * within the size it may take, is refused, never truncated or converted.
     *
     * @param  array<array-key, mixed>  $values
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideRefusedContexts')]
    public function testAContextRefusesWhatJsonDoesNotKeep(array $values, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        new ProviderContext($values); // @phpstan-ignore argument.type
    }

    /**
     * A context whose stored form, every character outside ASCII escaped
     * (twelve bytes for one outside the basic plane), takes exactly the most
     * bytes it may is kept; a byte more is refused, though it is far fewer
     * characters.
     *
     * @return void
     */
    public function testAContextIsRefusedWhenItsStoredFormDoesNotFit(): void
    {
        $fits = new ProviderContext(['k' => str_repeat("\u{1F600}", 340) . str_repeat('a', 8)]);

        self::assertSame(ProviderContext::STORED_MAX_BYTES, strlen($fits->toStored()));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(self::STORED);

        new ProviderContext(['k' => str_repeat("\u{1F600}", 340) . str_repeat('a', 9)]);
    }

    /**
     * The context keeps a copy of what it was given, so changing the given
     * array through a reference afterwards, at the top or nested, changes
     * neither its values nor its stored form.
     *
     * @return void
     */
    public function testAContextKeepsItsValuesByValue(): void
    {
        $values = ['protocol' => 'saml', 'link' => ['method' => 'domain']];
        $top    = &$values['protocol'];
        $nested = &$values['link']['method'];

        $context = new ProviderContext($values);

        $top    = 'oidc';
        $nested = 'explicit';

        self::assertSame(['protocol' => 'saml', 'link' => ['method' => 'domain']], $context->toArray());
        self::assertSame('{"protocol":"saml","link":{"method":"domain"}}', $context->toStored());
    }

    /**
     * The stored form reads back as the same values, the types JSON keeps kept,
     * and a stored form another encoder wrote (characters unescaped) is read as
     * its values.
     *
     * @return void
     */
    public function testTheStoredFormReadsBackAsTheSameContext(): void
    {
        $values  = ['protocol' => 'oidc', 'whole' => 2.0, 'large' => PHP_INT_MAX, 'name' => "Zoë \u{1F600}", 'nested' => [7 => ['a' => [null, false]]]];
        $context = new ProviderContext($values);

        self::assertSame($values, ProviderContext::fromStored($context->toStored())?->toArray());
        self::assertSame(['name' => 'Zoë'], ProviderContext::fromStored('{"name":"Zoë"}')?->toArray());
        self::assertSame(['a' => ['b' => ['c' => []]]], ProviderContext::fromStored('{"a":{"b":{"c":{}}}}')?->toArray());
    }

    /**
     * Rows of a stored value that holds no context.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedStoredValues(): iterable
    {
        yield from [
            'nothing'                   => [null],
            'a number'                  => [7],
            'an array already decoded'  => [['protocol' => 'saml']],
            'no text'                   => [''],
            'text that is not JSON'     => ['{"protocol":'],
            'a JSON string'             => ['"saml"'],
            'a JSON list'               => ['["saml"]'],
            'an empty JSON object'      => ['{}'],
            'a key PHP makes a number'  => ['{"7":"saml"}'],
            'a number JSON cannot keep' => ['{"a":1e400}'],
            'an unpaired surrogate'     => ['{"a":"\ud800"}'],
            'arrays nested too deep'    => ['{"a":[[[[1]]]]}'],
            'more than fits'            => ['{"a":"' . str_repeat('a', 4089) . '"}'],
        ];
    }

    /**
     * A stored value that is not the stored form, or whose values do not fit,
     * reads as no context rather than failing, so a contributor never sees it.
     *
     * @param  mixed  $value
     * @return void
     */
    #[DataProvider('provideMalformedStoredValues')]
    public function testAMalformedStoredValueIsNoContext(mixed $value): void
    {
        self::assertNull(ProviderContext::fromStored($value));
    }
}
