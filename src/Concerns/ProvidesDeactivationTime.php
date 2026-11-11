<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

/**
 * Provides a default `CanBeActive` implementation for a model that records its
 * deactivation as a nullable time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authentication\Contracts\CanBeActive
 */
trait ProvidesDeactivationTime
{
    /**
     * Return whether the model has no deactivation time.
     *
     * @return bool
     *
     * @throws \LogicException
     */
    public function isActive(): bool
    {
        $name       = $this->getDeactivatedAtName();
        $attributes = $this->getAttributes();

        if (!array_key_exists($name, $attributes)) {
            $message = sprintf(
                'Cannot determine whether %s is active: its `%s` attribute is not loaded.'
                . ' Select the column or override getDeactivatedAtName().',
                static::class,
                $name,
            );

            throw new \LogicException($message);
        }

        return $attributes[$name] === null;
    }

    /**
     * Column name holding the deactivation time.
     *
     * @return string
     */
    protected function getDeactivatedAtName(): string
    {
        return 'deactivated_at';
    }
}
