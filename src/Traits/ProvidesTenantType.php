<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Traits;

use BackedEnum;
use UnitEnum;

/**
 * Provides a default `HasType` implementation sourced from a
 * configurable Eloquent attribute. Resolves `BackedEnum` (`value`),
 * `UnitEnum` (`name`), and arbitrary string-castable values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
trait ProvidesTenantType
{
    /**
     * Return the tenant's type as a string. Resolves `BackedEnum`
     * via `value`, `UnitEnum` via `name`, otherwise casts to string.
     *
     * @return string
     */
    public function getType(): string
    {
        $value = $this->getAttribute($this->getTenantTypeName());

        if ($value instanceof \BackedEnum) {
            return (string) $value->value;
        }

        if ($value instanceof \UnitEnum) {
            return $value->name;
        }

        return (string) $value;
    }

    /**
     * Column name holding the tenant type.
     *
     * @return string
     */
    protected function getTenantTypeName(): string
    {
        return 'type';
    }
}
