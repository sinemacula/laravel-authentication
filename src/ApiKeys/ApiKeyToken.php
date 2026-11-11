<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ApiKeys;

use Random\Randomizer;

/**
 * The form of an API key, `<prefix>_<public>_<secret>`; a 238-bit secret needs
 * no password hash, so only its SHA-256 digest is stored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ApiKeyToken
{
    /** @var int Length of the random public part. */
    public const int PUBLIC_LENGTH = 16;

    /** @var int Length of the secret. */
    public const int SECRET_LENGTH = 40;

    /** @var string Pattern a presented key must match: its public part, then its secret. */
    private const string KEY_PATTERN = '/^([a-z][a-z0-9]{0,15}_[a-z0-9]{16})_([A-Za-z0-9]{40})$/D';

    /** @var string Pattern a presented public part (an OAuth client id) must match. */
    private const string PUBLIC_PATTERN = '/^[a-z][a-z0-9]{0,15}_[a-z0-9]{16}$/D';

    /** @var string Pattern a presented secret (an OAuth client secret) must match. */
    private const string SECRET_PATTERN = '/^[A-Za-z0-9]{40}$/D';

    /** @var string Characters of the public part. */
    private const string PUBLIC_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';

    /** @var string Characters of the secret. */
    private const string SECRET_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A new public part under the prefix.
     *
     * @param  string  $prefix
     * @return string
     */
    public static function newPublicPart(string $prefix): string
    {
        return $prefix . '_' . self::random(self::PUBLIC_ALPHABET, self::PUBLIC_LENGTH);
    }

    /**
     * A new secret.
     *
     * @return string
     */
    public static function newSecret(): string
    {
        return self::random(self::SECRET_ALPHABET, self::SECRET_LENGTH);
    }

    /**
     * The key a client presents, made of its public part and its secret.
     *
     * @param  string  $public
     * @param  string  $secret
     * @return string
     */
    public static function join(string $public, #[\SensitiveParameter] string $secret): string
    {
        return $public . '_' . $secret;
    }

    /**
     * The public part and the secret of a presented key, or `null` when it is
     * malformed.
     *
     * @param  string  $key
     * @return ?array{0: string, 1: string}
     */
    public static function split(#[\SensitiveParameter] string $key): ?array
    {
        return preg_match(self::KEY_PATTERN, $key, $matches) === 1 ? [$matches[1], $matches[2]] : null;
    }

    /**
     * Whether a presented public part and secret are each one in form.
     *
     * @param  string  $public
     * @param  string  $secret
     * @return bool
     */
    public static function isWellFormed(string $public, #[\SensitiveParameter] string $secret): bool
    {
        return self::isPublicPart($public) && preg_match(self::SECRET_PATTERN, $secret) === 1;
    }

    /**
     * Whether a presented public part (an OAuth client id) is well formed.
     *
     * @param  string  $public
     * @return bool
     */
    public static function isPublicPart(string $public): bool
    {
        return preg_match(self::PUBLIC_PATTERN, $public) === 1;
    }

    /**
     * The digest a secret is stored and compared as: SHA-256, in hex.
     *
     * @param  string  $secret
     * @return string
     */
    public static function digest(#[\SensitiveParameter] string $secret): string
    {
        return hash('sha256', $secret);
    }

    /**
     * A string of the length drawn uniformly from the alphabet.
     *
     * @param  non-empty-string  $alphabet
     * @param  positive-int  $length
     * @return string
     */
    private static function random(string $alphabet, int $length): string
    {
        return (new Randomizer)->getBytesFromString($alphabet, $length);
    }
}
