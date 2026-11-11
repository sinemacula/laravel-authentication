<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

/**
 * Provides a default `CanBeActive` implementation read from a boolean
 * attribute.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authentication\Contracts\CanBeActive
 */
trait ProvidesActiveState
{
    /**
     * Return whether the model is currently eligible to authenticate.
     *
     * @return bool
     *
     * @throws \LogicException
     */
    public function isActive(): bool
    {
        $name = $this->getActiveAttributeName();

        if (!array_key_exists($name, $this->getAttributes())) {
            $message = sprintf(
                'Cannot determine whether %s is active: its `%s` attribute is not loaded.'
                . ' Select the column or override getActiveAttributeName().',
                static::class,
                $name,
            );

            throw new \LogicException($message);
        }

        return (bool) $this->getAttribute($name);
    }

    /**
     * Column name holding the active flag.
     *
     * @return string
     */
    protected function getActiveAttributeName(): string
    {
        return 'is_active';
    }
}
