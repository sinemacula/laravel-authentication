<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

/**
 * Refresh-token rotation-id hashing primitive.
 *
 * Refresh tokens carry an opaque high-entropy rotation identifier in the `jti`
 * claim. The server stores a SHA-256 digest on the device row and compares
 * candidates in constant time via `hash_equals()`.
 *
 * SHA-256, not bcrypt/argon2: the plaintext is already a 256-bit random value
 * (or derived from one by `successor()`) so a slow KDF adds no security.
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
     * Deterministic, so a retry of a rotated refresh token inside the grace
     * window can be handed the current rotation id again without the server
     * storing any rotation id in plaintext: the presented, signed token holds
     * the previous id, and the successor of it must match the stored current
     * digest. Knowing a future id gives nothing away, because a rotation id is
     * only usable inside a token signed with the guard's key, and the device
     * row holds only SHA-256 digests, from which no id can be derived.
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
