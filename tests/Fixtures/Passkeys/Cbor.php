<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Passkeys;

/**
 * The subset of CBOR (RFC 8949) an authenticator writes: integers, byte
 * strings, text strings and maps, in definite lengths. Strings are byte strings
 * unless wrapped with `text()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Cbor
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Mark a string to be encoded as a text string rather than bytes.
     *
     * @param  string  $value
     * @return \Stringable
     */
    public static function text(string $value): \Stringable
    {
        return new class ($value) implements \Stringable {
            /**
             * Constructor.
             *
             * @param  string  $value
             */
            public function __construct(

                /** The text to encode. */
                private readonly string $value,
            ) {}

            /**
             * The text.
             *
             * @return string
             */
            #[\Override]
            public function __toString(): string
            {
                return $this->value;
            }
        };
    }

    /**
     * Encode the value: an integer, a byte string, a text string, or a map
     * given as a list of `[key, value]` pairs, so keys keep their order and
     * type.
     *
     * @param  int|list<array{0: int|string|\Stringable, 1: mixed}>|string|\Stringable  $value
     * @return string
     */
    public static function encode(mixed $value): string
    {
        return match (true) {
            is_int($value)                => $value >= 0 ? self::head(0, $value) : self::head(1, -1 - $value),
            is_string($value)             => self::head(2, strlen($value)) . $value,
            $value instanceof \Stringable => self::head(3, strlen((string) $value)) . $value,
            default                       => self::map($value),
        };
    }

    /**
     * Encode a map of `[key, value]` pairs.
     *
     * @param  list<array{0: int|string|\Stringable, 1: mixed}>  $pairs
     * @return string
     */
    private static function map(array $pairs): string
    {
        $encoded = self::head(5, count($pairs));

        foreach ($pairs as [$key, $item]) {
            $encoded .= self::encode($key) . self::encode($item);
        }

        return $encoded;
    }

    /**
     * Encode a major type and its argument.
     *
     * @param  int  $major
     * @param  int  $argument
     * @return string
     */
    private static function head(int $major, int $argument): string
    {
        return match (true) {
            $argument < 24      => chr(($major << 5) | $argument),
            $argument < 0x100   => chr(($major << 5) | 24) . chr($argument),
            $argument < 0x10000 => chr(($major << 5) | 25) . pack('n', $argument),
            default             => chr(($major << 5) | 26) . pack('N', $argument),
        };
    }
}
