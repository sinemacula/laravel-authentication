<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

/**
 * An object that makes closures bound to itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ClosureOwnerFixture
{
    /**
     * Constructor.
     *
     * @param  string  $label
     */
    public function __construct(

        /** What the owner's closures answer. */
        private string $label,
    ) {}

    /**
     * An anonymous closure bound to the owner.
     *
     * @return \Closure(): string
     */
    public function closure(): \Closure
    {
        return fn (): string => $this->label;
    }

    /**
     * The owner's label.
     *
     * @return string
     */
    public function name(): string
    {
        return $this->label;
    }
}
