<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Requirements;

use Carbon\CarbonImmutable;

/**
 * A check's answer about a requirement: the kinds of part the session does not
 * meet, and until when a met answer holds.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RequirementEvaluation
{
    /**
     * Constructor.
     *
     * @param  list<\SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind>  $unmet
     * @param  ?\Carbon\CarbonImmutable  $metUntil
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The kinds of part the session does not meet. */
        public array $unmet,

        /** When a met answer stops holding as its proofs age, were the proofs and policy unchanged; `null` for no such time. */
        public ?CarbonImmutable $metUntil = null,
    ) {
        if ($unmet !== [] && $metUntil !== null) {
            throw new \InvalidArgumentException('A requirement evaluation with unmet parts has no time it is met until.');
        }
    }

    /**
     * Whether the session meets the requirement.
     *
     * @return bool
     */
    public function isMet(): bool
    {
        return $this->unmet === [];
    }
}
