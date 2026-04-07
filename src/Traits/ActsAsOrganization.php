<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Traits;

use BackedEnum;
use UnitEnum;

/**
 * Provides default Organization contract method implementations
 * sourced from configurable Eloquent model attribute names.
 *
 * Scope resolution handles `BackedEnum` (returns `value`),
 * `UnitEnum` (returns `name`), and arbitrary string-castable values.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
trait ActsAsOrganization
{
    /**
     * Return the organization's stable identifier from the configured attribute.
     *
     * @return mixed
     */
    public function getOrganizationIdentifier(): mixed
    {
        return $this->getAttribute($this->getOrganizationIdentifierName());
    }

    /**
     * Return the organization's scope as a string.
     *
     * Resolution precedence:
     *  1. `BackedEnum` values are resolved via the backing `value`
     *     (cast to string to cover integer-backed enums).
     *  2. Non-backed `UnitEnum` values are resolved via `name`.
     *  3. Anything else is cast to string (covers plain strings and
     *     `Stringable` objects).
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
     * Column name holding the organization identifier. Override in the consuming model to remap.
     *
     * @return string
     */
    protected function getOrganizationIdentifierName(): string
    {
        return 'id';
    }

    /**
     * Column name holding the organization scope. Override in the consuming model to remap.
     *
     * @return string
     */
    protected function getOrganizationScopeName(): string
    {
        return 'scope';
    }
}
