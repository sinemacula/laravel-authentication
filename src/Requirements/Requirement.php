<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Requirements;

use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;

/**
 * What a session's authentication must include beyond its first factor; with no
 * parts it asks for nothing.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Requirement
{
    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Requirements\RequirementPart  $additionalVerification
     * @param  ?\SineMacula\Laravel\Authentication\Requirements\RequirementPart  $multifactor
     * @param  ?\SineMacula\Laravel\Authentication\Requirements\LevelRequirement  $minimumLevel
     * @param  ?\SineMacula\Laravel\Authentication\Requirements\RequirementPart  $phishingResistance
     */
    public function __construct(

        /** A further factor beyond the first, if one is required. */
        public ?RequirementPart $additionalVerification = null,

        /** Multifactor authentication, if it is required. */
        public ?RequirementPart $multifactor = null,

        /** A minimum assurance level, if one is required. */
        public ?LevelRequirement $minimumLevel = null,

        /** A phishing-resistant authenticator, if one is required. */
        public ?RequirementPart $phishingResistance = null,
    ) {}

    /**
     * The strictest requirement the given ones make together.
     *
     * @param  self  ...$requirements
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function strictest(self ...$requirements): self
    {
        $strictest = new self;

        foreach ($requirements as $requirement) {
            $strictest = new self(
                self::stricterPart($strictest->additionalVerification, $requirement->additionalVerification),
                self::stricterPart($strictest->multifactor, $requirement->multifactor),
                self::stricterLevel($strictest->minimumLevel, $requirement->minimumLevel),
                self::stricterPart($strictest->phishingResistance, $requirement->phishingResistance),
            );
        }

        return $strictest;
    }

    /**
     * Whether the requirement asks for nothing.
     *
     * @return bool
     */
    public function isEmpty(): bool
    {
        return $this->kinds() === [];
    }

    /**
     * The kinds of part the requirement has, in the order it lists them.
     *
     * @return list<\SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind>
     */
    public function kinds(): array
    {
        $parts = [
            RequirementKind::ADDITIONAL_VERIFICATION->value => $this->additionalVerification,
            RequirementKind::MULTIFACTOR->value             => $this->multifactor,
            RequirementKind::MINIMUM_LEVEL->value           => $this->minimumLevel,
            RequirementKind::PHISHING_RESISTANCE->value     => $this->phishingResistance,
        ];

        return array_map(RequirementKind::from(...), array_keys(array_filter($parts, static fn (?object $part): bool => $part !== null)));
    }

    /**
     * The stricter of two parts: either one when the other is absent, else a
     * part with the shorter maximum age.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Requirements\RequirementPart  $first
     * @param  ?\SineMacula\Laravel\Authentication\Requirements\RequirementPart  $second
     * @return ?\SineMacula\Laravel\Authentication\Requirements\RequirementPart
     *
     * @throws \InvalidArgumentException
     */
    private static function stricterPart(?RequirementPart $first, ?RequirementPart $second): ?RequirementPart
    {
        if ($first === null || $second === null) {
            return $first ?? $second;
        }

        return new RequirementPart(RequirementPart::shorter($first->maxAgeSeconds, $second->maxAgeSeconds));
    }

    /**
     * The stricter of two minimum levels: either one when the other is absent,
     * else the higher level with the shorter maximum age.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Requirements\LevelRequirement  $first
     * @param  ?\SineMacula\Laravel\Authentication\Requirements\LevelRequirement  $second
     * @return ?\SineMacula\Laravel\Authentication\Requirements\LevelRequirement
     *
     * @throws \InvalidArgumentException
     */
    private static function stricterLevel(?LevelRequirement $first, ?LevelRequirement $second): ?LevelRequirement
    {
        if ($first === null || $second === null) {
            return $first ?? $second;
        }

        $level = $first->level->isAtLeast($second->level) ? $first->level : $second->level;

        return new LevelRequirement($level, RequirementPart::shorter($first->maxAgeSeconds, $second->maxAgeSeconds));
    }
}
