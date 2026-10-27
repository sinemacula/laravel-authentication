<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

/**
 * Provides a default `HasType` implementation, for a principal or a tenant,
 * sourced from a configurable Eloquent attribute. Resolves `BackedEnum`
 * (`value`), `UnitEnum` (`name`), and arbitrary string-castable values.
 *
 * The attribute must be loaded, or have an accessor: a model selected without
 * it throws rather than reporting no type, which would let a principal take its
 * tenant's type in place of its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authentication\Contracts\HasType
 */
trait ProvidesType
{
    /**
     * Return the model's type as a string. Resolves `BackedEnum` via `value`,
     * `UnitEnum` via `name`, otherwise casts to string.
     *
     * @return string
     *
     * @throws \LogicException
     */
    public function getType(): string
    {
        $name = $this->getTypeAttributeName();

        if (!array_key_exists($name, $this->getAttributes()) && !$this->hasAnyGetMutator($name)) {

            $message = sprintf(
                'Cannot read the type of %s: its `%s` attribute is not loaded. Select the column or override getTypeAttributeName().',
                static::class,
                $name,
            );

            throw new \LogicException($message);
        }

        $value = $this->getAttribute($name);

        if ($value instanceof \BackedEnum) {
            return (string) $value->value;
        }

        if ($value instanceof \UnitEnum) {
            return $value->name;
        }

        return (string) $value;
    }

    /**
     * Column name holding the type.
     *
     * @return string
     */
    protected function getTypeAttributeName(): string
    {
        return 'type';
    }
}
