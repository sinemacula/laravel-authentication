<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Casts;

use Illuminate\Container\Container;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalizers;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;

/**
 * Designates an identity attribute as an identifier of a type, so it is stored
 * and looked up in its normal form.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Database\Eloquent\CastsAttributes<mixed, ?string>
 */
final readonly class NormalizedIdentifier implements CastsAttributes
{
    /**
     * Constructor.
     *
     * @param  string  $type
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** Identifier type, which names the normaliser. */
        public string $type,
    ) {
        IdentifierType::assertValid($type);
    }

    /**
     * The cast declaration for an identifier of the type, for an identity
     * model's `casts()`.
     *
     * @param  string  $type
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function using(string $type): string
    {
        return self::class . ':' . IdentifierType::assertValid($type);
    }

    /**
     * The cast a model's cast declaration makes, or `null` when it designates
     * no identifier.
     *
     * @param  mixed  $declaration
     * @return ?self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromDeclaration(mixed $declaration): ?self
    {
        $prefix = self::class . ':';

        if (!is_string($declaration) || !str_starts_with($declaration, $prefix)) {
            return null;
        }

        return new self(substr($declaration, strlen($prefix)));
    }

    /**
     * Return the stored value unchanged.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $key
     * @param  mixed  $value
     * @param  array<string, mixed>  $attributes
     * @return mixed
     */
    #[\Override]
    public function get(Model $model, string $key, mixed $value, array $attributes): mixed
    {
        return $value;
    }

    /**
     * Store the value in its normal form; `null` stays `null`.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  string  $key
     * @param  mixed  $value
     * @param  array<string, mixed>  $attributes
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function set(Model $model, string $key, #[\SensitiveParameter] mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }

        $normalized = is_string($value) || $value instanceof \Stringable ? $this->normalize((string) $value) : null;

        if ($normalized === null) {
            throw new \InvalidArgumentException(sprintf('Cannot set `%s` on %s: the value is not a valid `%s` identifier.', $key, $model::class, $this->type));
        }

        return $normalized;
    }

    /**
     * Normalise a value with the type's normaliser, or `null` when it cannot be
     * an identifier of the type.
     *
     * @param  string  $identifier
     * @return ?string
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function normalize(#[\SensitiveParameter] string $identifier): ?string
    {
        return Container::getInstance()->make(IdentifierNormalizers::class)->get($this->type)->normalize($identifier);
    }
}
