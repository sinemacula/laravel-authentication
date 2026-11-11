<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\External;

/**
 * Details of how an external identity provider established a session, opaque to
 * this package.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ProviderContext
{
    /** @var int Most bytes the context takes as stored, in JSON. */
    public const int STORED_MAX_BYTES = 4096;

    /** @var int Deepest nesting of arrays, the map itself the first. */
    public const int MAX_DEPTH = 4;

    /** @var int The flags the stored form is encoded with: a float stays a float, `1.0` included. */
    private const int ENCODING = JSON_THROW_ON_ERROR | JSON_PRESERVE_ZERO_FRACTION;

    /** @var array<string, mixed> The contributing package's own keys and values, opaque to this package. */
    public array $values;

    /** @var string The values as stored: JSON, ASCII only. */
    private string $stored;

    /**
     * Constructor.
     *
     * @param  array<string, mixed>  $values
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(array $values)
    {
        $this->values = self::map($values);
        $this->stored = self::encode($this->values);
    }

    /**
     * The values, as given.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->values;
    }

    /**
     * The values as the provenance stores them.
     *
     * @internal
     *
     * @return string
     */
    public function toStored(): string
    {
        return $this->stored;
    }

    /**
     * The context a stored value holds, or `null` when it holds none or is
     * malformed.
     *
     * @internal
     *
     * @param  mixed  $value
     * @return ?self
     */
    public static function fromStored(mixed $value): ?self
    {
        try {
            $values = is_string($value) ? json_decode($value, true, flags: JSON_THROW_ON_ERROR) : null;
            $map    = is_array($values) ? array_filter($values, is_string(...), ARRAY_FILTER_USE_KEY) : null;

            return $map !== null && $map === $values ? new self($map) : null;
        } catch (\InvalidArgumentException|\JsonException) {
            return null;
        }
    }

    /**
     * A copy of the map, refused unless it is a non-empty map with string keys
     * whose values fit.
     *
     * @param  array<array-key, mixed>  $values
     * @return array<string, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private static function map(array $values): array
    {
        $map = [];

        foreach ($values as $key => $value) {

            if (!is_string($key)) {
                throw new \InvalidArgumentException('A provider context must be a map with string keys.');
            }

            $map[$key] = self::value($value, 1);
        }

        if ($map === []) {
            throw new \InvalidArgumentException('A provider context must hold at least one value; give none for no context.');
        }

        return $map;
    }

    /**
     * A copy of a value nested `$depth` deep, refused unless it is `null`, a
     * scalar or an array of those.
     *
     * @param  mixed  $value
     * @param  int  $depth
     * @return mixed
     *
     * @throws \InvalidArgumentException
     */
    private static function value(mixed $value, int $depth): mixed
    {
        if (is_array($value)) {
            return self::nested($value, $depth + 1);
        }

        if ($value !== null && !is_scalar($value)) {
            throw new \InvalidArgumentException('A provider context\'s values must be null, booleans, numbers, strings or arrays of them.');
        }

        return $value;
    }

    /**
     * A copy of an array nested `$depth` deep, refused when that is deeper than
     * `MAX_DEPTH`.
     *
     * @param  array<array-key, mixed>  $values
     * @param  int  $depth
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private static function nested(array $values, int $depth): array
    {
        if ($depth > self::MAX_DEPTH) {
            throw new \InvalidArgumentException(sprintf('A provider context may nest arrays at most %d deep.', self::MAX_DEPTH));
        }

        $copy = [];

        foreach ($values as $key => $value) {
            $copy[$key] = self::value($value, $depth);
        }

        return $copy;
    }

    /**
     * The stored form of the values, refused when they cannot be encoded or
     * exceed `STORED_MAX_BYTES`.
     *
     * @param  array<string, mixed>  $values
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function encode(array $values): string
    {
        try {
            $stored = json_encode($values, self::ENCODING);
        } catch (\JsonException) {
            $stored = null;
        }

        if ($stored === null || strlen($stored) > self::STORED_MAX_BYTES) {

            $message = sprintf(
                'A provider context must be valid UTF-8, hold only finite numbers and take at most %d bytes as stored.',
                self::STORED_MAX_BYTES,
            );

            throw new \InvalidArgumentException($message);
        }

        return $stored;
    }
}
