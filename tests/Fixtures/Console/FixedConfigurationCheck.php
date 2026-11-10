<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Console;

use SineMacula\Laravel\Authentication\Contracts\ConfigurationCheck;

/**
 * A configuration check that answers the findings it was given, or throws what
 * it was given, and keeps the guards it was asked about.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class FixedConfigurationCheck implements ConfigurationCheck
{
    /** @var ?list<string> The guards the last ask named, or `null` before one. */
    public ?array $asked = null;

    /**
     * Constructor.
     *
     * @param  mixed  $answer
     * @param  ?\Throwable  $throws
     */
    public function __construct(

        /** The answer to give: findings, or anything else to see it reported. */
        private readonly mixed $answer = [],

        /** What to throw instead of answering. */
        private readonly ?\Throwable $throws = null,
    ) {}

    /**
     * The findings it was given, or throw what it was given.
     *
     * @param  list<string>  $guards
     * @return list<\SineMacula\Laravel\Authentication\Console\ConfigurationFinding>
     *
     * @throws \Throwable
     */
    #[\Override]
    public function findings(array $guards): array
    {
        $this->asked = $guards;

        if ($this->throws !== null) {
            throw $this->throws;
        }

        /** @var list<\SineMacula\Laravel\Authentication\Console\ConfigurationFinding> */
        return $this->answer;
    }
}
