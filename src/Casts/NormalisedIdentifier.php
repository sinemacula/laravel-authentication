<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Casts;

use Illuminate\Container\Container;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalisers;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;

/**
 * Designates an identity attribute as an identifier of a type, so it is stored
 * in its normal form and looked up in it.
 *
 * Declare it on the identity model with the identifier type as its argument:
 *
 *     protected function casts(): array
 *     {
 *         return ['email' => NormalisedIdentifier::using('email')];
 *     }
 *
 * Setting the attribute stores the value as the type's normaliser returns it
 * (`Ben@Example.com ` becomes `ben@example.com`), and the `model` provider
 * normalises a credential for the attribute the same way before it queries, so
 * lookups match on every database whatever its collation. Reading returns the
 * stored value unchanged: rows written before the cast was added keep their
 * form until they are normalised (see the README on uniqueness).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @implements \Illuminate\Contracts\Database\Eloquent\CastsAttributes<mixed, ?string>
 */
final readonly class NormalisedIdentifier implements CastsAttributes
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
     * The cast a model's cast declaration makes, when it designates an
     * identifier, otherwise `null`.
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

        $normalised = is_string($value) || $value instanceof \Stringable ? $this->normalise((string) $value) : null;

        if ($normalised === null) {
            throw new \InvalidArgumentException(sprintf('Cannot set `%s` on %s: the value is not a valid `%s` identifier.', $key, $model::class, $this->type));
        }

        return $normalised;
    }

    /**
     * Normalise a value with the type's normaliser: `null` when it cannot be an
     * identifier of the type.
     *
     * @param  string  $identifier
     * @return ?string
     *
     * @throws \InvalidArgumentException
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function normalise(#[\SensitiveParameter] string $identifier): ?string
    {
        return Container::getInstance()->make(IdentifierNormalisers::class)->get($this->type)->normalise($identifier);
    }
}
