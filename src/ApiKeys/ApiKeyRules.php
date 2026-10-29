<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ApiKeys;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * What issuing or rotating a key accepts: the principal, the name, the expiry
 * and the rotation overlap. Each is a trusted caller's choice, so one out of
 * bounds is an `InvalidArgumentException`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ApiKeyRules
{
    /** @var int Longest name a key may be given, in characters. */
    private const int MAX_NAME_LENGTH = 255;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The principal a key may be issued for: the one the resolver returned,
     * which the audience admitted.
     *
     * @param  string  $guard
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $resolved
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $refusal
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \InvalidArgumentException
     */
    public static function principal(string $guard, ?Principal $resolved, ?FailureReason $refusal): Principal
    {
        if ($resolved === null) {
            throw new \InvalidArgumentException("An API key of guard [{$guard}] can only be issued for a principal the identity acts as.");
        }

        if ($refusal !== null) {
            throw new \InvalidArgumentException("The audience of guard [{$guard}] does not admit the principal an API key was to be issued for ({$refusal->value}).");
        }

        return $resolved;
    }

    /**
     * The key's name: `null`, or a string of 1 to 255 characters of valid UTF-8
     * without a NUL byte.
     *
     * @param  ?string  $name
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public static function name(?string $name): ?string
    {
        if ($name !== null && !self::isWellFormedName($name)) {
            throw new \InvalidArgumentException('An API key\'s name must be null or 1 to ' . self::MAX_NAME_LENGTH . ' characters of valid UTF-8 without a NUL byte.');
        }

        return $name;
    }

    /**
     * The key's expiry in whole seconds, which must be after now, or `null`.
     *
     * @param  ?\Carbon\CarbonInterface  $expiresAt
     * @param  \Carbon\CarbonImmutable  $now
     * @return ?\Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    public static function expiry(?CarbonInterface $expiresAt, CarbonImmutable $now): ?CarbonImmutable
    {
        if ($expiresAt === null) {
            return null;
        }

        $expiry = CarbonImmutable::instance($expiresAt)->startOfSecond();

        if ($expiry->getTimestamp() <= $now->getTimestamp()) {
            throw new \InvalidArgumentException('An API key\'s expiry must be in the future.');
        }

        return $expiry;
    }

    /**
     * The rotation's overlap: the one given, or the configured default, from 0
     * to the configured maximum.
     *
     * @param  ?int  $overlapSeconds
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public static function overlap(?int $overlapSeconds): int
    {
        $overlap = $overlapSeconds ?? ApiKeySettings::rotationOverlapSeconds();
        $max     = ApiKeySettings::maxRotationOverlapSeconds();

        if ($overlap < 0 || $overlap > $max) {
            throw new \InvalidArgumentException("An API key's rotation overlap must be from 0 to {$max} seconds (`authentication.api_keys.max_rotation_overlap_seconds`).");
        }

        return $overlap;
    }

    /**
     * Whether the name is 1 to 255 characters of valid UTF-8 without a NUL
     * byte; PostgreSQL would store a name cut short at its first NUL byte.
     *
     * @param  string  $name
     * @return bool
     */
    private static function isWellFormedName(string $name): bool
    {
        if ($name === '' || str_contains($name, "\0")) {
            return false;
        }

        return mb_check_encoding($name, 'UTF-8') && mb_strlen($name, 'UTF-8') <= self::MAX_NAME_LENGTH;
    }
}
