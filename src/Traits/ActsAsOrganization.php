<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Traits;

use BackedEnum;
use UnitEnum;

/**
 * Provides default Organization contract implementations sourced
 * from configurable Eloquent attribute names. Scope resolution
 * handles `BackedEnum` (`value`), `UnitEnum` (`name`), and arbitrary
 * string-castable values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
trait ActsAsOrganization
{
    /**
     * Return the organization's stable identifier from the
     * configured attribute.
     *
     * @return mixed
     */
    public function getOrganizationIdentifier(): mixed
    {
        return $this->getAttribute($this->getOrganizationIdentifierName());
    }

    /**
     * Return the organization's scope as a string. Resolves
     * `BackedEnum` via `value`, `UnitEnum` via `name`, otherwise
     * casts to string.
     *
     * @return string
     */
    public function getOrganizationScope(): string
    {
        $value = $this->getAttribute($this->getOrganizationScopeName());

        if ($value instanceof \BackedEnum) {
            return (string) $value->value;
        }

        if ($value instanceof \UnitEnum) {
            return $value->name;
        }

        return (string) $value;
    }

    /**
     * Column name holding the organization identifier.
     *
     * @return string
     */
    protected function getOrganizationIdentifierName(): string
    {
        return 'id';
    }

    /**
     * Column name holding the organization scope.
     *
     * @return string
     */
    protected function getOrganizationScopeName(): string
    {
        return 'scope';
    }
}
