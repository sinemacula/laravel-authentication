<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

/**
 * Provides a default `CanBeActive` implementation for a model that records its
 * deactivation as a time: a nullable column (`deactivated_at` by default) that
 * is `null` while the model is active. Override `getDeactivatedAtName()` to
 * remap the column. It is the timestamp form of `ProvidesActiveState`, which
 * reads a boolean flag; a model uses one or the other.
 *
 * The using class must also implement `CanBeActive`: activation is checked only
 * on models that declare the capability, so the trait on its own is never
 * consulted.
 *
 * The model is active exactly while the column's value is `null`. Any other
 * value means inactive, whether the time it holds is past, present or future: a
 * deactivation scheduled for later is the application's to write when it falls
 * due. The value is read as the model holds it (`getAttributes()`, unsaved
 * changes included), not cast, so a stored time that cannot be parsed reads
 * inactive rather than throwing.
 *
 * The attribute must be loaded: a model selected without the column throws
 * rather than being read as either active or inactive, so a partial select
 * surfaces as a misconfiguration instead of silently changing who can sign in.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authentication\Contracts\CanBeActive
 */
trait ProvidesDeactivationTime
{
    /**
     * Return whether the model is currently eligible to authenticate: whether
     * it has no deactivation time.
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
