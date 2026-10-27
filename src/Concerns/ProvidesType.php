<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

/**
 * Provides a default `HasType` implementation, for a principal or a tenant,
 * sourced from a configurable Eloquent attribute. Resolves `BackedEnum`
 * (`value`), `UnitEnum` (`name`), and arbitrary string-castable values.
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
     */
    public function getType(): string
    {
        $value = $this->getAttribute($this->getTypeAttributeName());

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
