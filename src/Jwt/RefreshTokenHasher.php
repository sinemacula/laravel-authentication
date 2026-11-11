<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

/**
 * Generates, derives and hashes refresh-token rotation ids.
 *
 * SHA-256 suffices: the plaintext is already a 256-bit random value, so a slow
 * KDF adds no security.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class RefreshTokenHasher
{
    /** @var int Number of random bytes per rotation id. */
    private const int ROTATION_ID_BYTES = 32;

    /** @var string Domain-separation label for deriving the next rotation id. */
    private const string SUCCESSOR_LABEL = 'sinemacula.laravel-authentication.refresh-rotation.v1';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Generate a cryptographically random rotation identifier as URL-safe
     * base64 with no padding.
     *
     * @return string
     *
     * @throws \Random\RandomException
     */
    public static function generate(): string
    {
        return self::encode(random_bytes(self::ROTATION_ID_BYTES));
    }

    /**
     * Derive the rotation id that replaces the given one: an HMAC-SHA256 keyed
     * by the plaintext id, encoded like `generate()`.
     *
     * @param  string  $rotationId
     * @return string
     */
    public static function successor(#[\SensitiveParameter] string $rotationId): string
    {
        return self::encode(hash_hmac('sha256', self::SUCCESSOR_LABEL, $rotationId, true));
    }

    /**
     * Constant-time verification of a plaintext rotation identifier against a
     * stored digest.
     *
     * @param  string  $rotationId
     * @param  string  $storedDigest
     * @return bool
     */
    public static function verify(#[\SensitiveParameter] string $rotationId, string $storedDigest): bool
    {
        if ($storedDigest === '' || $rotationId === '') {
            return false;
        }

        return hash_equals($storedDigest, self::hash($rotationId));
    }

    /**
     * Hash a plaintext rotation identifier for storage on the session row.
     *
     * @param  string  $rotationId
     * @return string
     */
    public static function hash(#[\SensitiveParameter] string $rotationId): string
    {
        return hash('sha256', $rotationId);
    }

    /**
     * Encode raw bytes as URL-safe base64 with no padding.
     *
     * @param  string  $bytes
     * @return string
     */
    private static function encode(#[\SensitiveParameter] string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
