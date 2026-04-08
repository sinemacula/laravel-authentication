<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

/**
 * Refresh-token rotation-id hashing primitive.
 *
 * Refresh tokens carry an opaque high-entropy rotation identifier in
 * the `jti` claim. The server stores a SHA-256 digest on the device
 * row and compares candidates in constant time via `hash_equals()`.
 *
 * SHA-256 is intentional rather than bcrypt/argon2: the plaintext is
 * already a 256-bit random value so a slow KDF adds no meaningful
 * security, refresh verification runs on every exchange and must be
 * fast, and the deterministic digest keeps the stored value indexable.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class RefreshTokenHasher
{
    /** @var int Number of random bytes per rotation id. */
    private const int ROTATION_ID_BYTES = 32;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Generate a cryptographically random rotation identifier as
     * URL-safe base64 with no padding.
     *
     * @return string
     */
    public static function generate(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(self::ROTATION_ID_BYTES)), '+/', '-_'), '=');
    }

    /**
     * Hash a plaintext rotation identifier for storage on the device row.
     *
     * @param  string  $rotationId
     * @return string
     */
    public static function hash(#[\SensitiveParameter] string $rotationId): string
    {
        return hash('sha256', $rotationId);
    }

    /**
     * Constant-time verification of a plaintext rotation identifier
     * against a stored digest.
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
}
