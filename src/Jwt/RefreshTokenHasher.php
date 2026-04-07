<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

/**
 * Refresh-token rotation-id hashing primitive.
 *
 * Refresh tokens carry an opaque high-entropy rotation identifier in
 * the `jti` claim. The server never stores the plaintext — it stores
 * a SHA-256 digest of it on the device row and compares candidates
 * in constant time via `hash_equals()`.
 *
 * SHA-256 is the right primitive here (rather than bcrypt/argon2)
 * because:
 * - the plaintext is already a 256-bit random value, so a slow KDF
 *   adds no meaningful security against brute force,
 * - refresh-token verification runs on every refresh exchange and
 *   must be fast,
 * - the digest is deterministic, which keeps the stored value
 *   indexable if consumers ever need to look up by refresh key
 *   (the default flow looks up by `did` instead).
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
final class RefreshTokenHasher
{
    /** @var int Number of random bytes generated for each rotation id. */
    private const int ROTATION_ID_BYTES = 32;

    /**
     * Disallow instantiation: utility container only.
     */
    private function __construct() {}

    /**
     * Generate a fresh cryptographically random rotation identifier
     * as URL-safe base64 (no padding).
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
