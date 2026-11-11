<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use Carbon\CarbonInterface;

/**
 * Default `HasTokensValidAfter` implementation for an Eloquent identity or
 * principal, over a nullable `tokens_valid_after` column.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter
 */
trait ProvidesTokensValidAfter
{
    /**
     * Return the time at or before which access tokens issued without a session
     * are rejected, or `null` when there is none.
     *
     * @return ?\Carbon\CarbonInterface
     *
     * @throws \LogicException
     */
    public function getTokensValidAfter(): ?CarbonInterface
    {
        $name = $this->getTokensValidAfterName();

        if (!array_key_exists($name, $this->getAttributes())) {

            $message = sprintf(
                'Cannot read when the tokens of %s become valid: its `%s` attribute is not loaded.'
                . ' Select the column or override getTokensValidAfterName().',
                static::class,
                $name,
            );

            throw new \LogicException($message);
        }

        $value = $this->getAttribute($name);

        return $value === null || $value instanceof CarbonInterface ? $value : $this->asDateTime($value);
    }

    /**
     * Move the cutoff forward to `$time`, never back, and answer whether it
     * moved.
     *
     * @param  \Carbon\CarbonInterface  $time
     * @return bool
     *
     * @imperative
     */
    public function invalidateTokensIssuedBefore(CarbonInterface $time): bool
    {
        $name = $this->getTokensValidAfterName();
        $at   = $this->fromDateTime($time);

        $affected = $this->getConnection()
            ->table($this->getTable())
            ->where($this->getKeyName(), $this->getKey())
            ->where(static fn ($query) => $query->whereNull($name)->orWhere($name, '<', $at))
            ->update([$name => $at]);

        if ($affected !== 1) {
            return false;
        }

        $this->forceFill([$name => $at])->syncOriginalAttributes([$name]);

        return true;
    }

    /**
     * Column name holding the cutoff.
     *
     * @return string
     */
    protected function getTokensValidAfterName(): string
    {
        return 'tokens_valid_after';
    }
}
