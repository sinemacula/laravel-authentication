<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Requirements;

/**
 * One part of a requirement, met by proofs of any age or only by those made
 * within its maximum age.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RequirementPart
{
    /** @var int The longest maximum age a part may set: a year, in seconds. */
    public const int MAX_AGE_SECONDS = 31536000;

    /**
     * Constructor.
     *
     * @param  ?int  $maxAgeSeconds
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** How recent a proof meeting the part must be, in seconds; `null` for any age. */
        public ?int $maxAgeSeconds = null,
    ) {
        self::assertMaxAge($maxAgeSeconds);
    }

    /**
     * The shorter of two maximum ages, where `null` is any age.
     *
     * @param  ?int  $first
     * @param  ?int  $second
     * @return ?int
     */
    public static function shorter(?int $first, ?int $second): ?int
    {
        return $first === null || $second === null ? $first ?? $second : min($first, $second);
    }

    /**
     * Refuse a maximum age outside 1 to `MAX_AGE_SECONDS` seconds.
     *
     * @param  ?int  $maxAgeSeconds
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertMaxAge(?int $maxAgeSeconds): void
    {
        if ($maxAgeSeconds !== null && ($maxAgeSeconds < 1 || $maxAgeSeconds > self::MAX_AGE_SECONDS)) {
            throw new \InvalidArgumentException(sprintf('A requirement\'s maximum age must be between 1 and %d seconds.', self::MAX_AGE_SECONDS));
        }
    }
}
