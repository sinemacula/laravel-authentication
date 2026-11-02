<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Requirements;

use SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel;

/**
 * The minimum-level part of a requirement: an assurance level, met by proofs of
 * any age or only by those made within its maximum age.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class LevelRequirement
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Requirements\Enums\AssuranceLevel  $level
     * @param  ?int  $maxAgeSeconds
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The lowest assurance level that meets the part. */
        public AssuranceLevel $level,

        /** How recent a proof meeting the part must be, in seconds; `null` for any age. */
        public ?int $maxAgeSeconds = null,
    ) {
        RequirementPart::assertMaxAge($maxAgeSeconds);
    }
}
