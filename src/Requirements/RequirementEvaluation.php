<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Requirements;

/**
 * A check's answer about a requirement: the kinds of part the session does not
 * meet.
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
     */
    public function __construct(

        /** The kinds of part the session does not meet. */
        public array $unmet,
    ) {}

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
