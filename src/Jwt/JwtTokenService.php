<?php

declare(strict_types=1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Carbon\Carbon;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use Throwable;

/**
 * JWT issue/parse service.
 *
 * Encapsulates `firebase/php-jwt` so the guards do not import it
 * directly. Single-purpose: issue access tokens, issue refresh tokens,
 * decode and verify tokens, decode tokens that may be expired.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
final class JwtTokenService
{
    public function __construct(

        /** Shared secret used for HMAC algorithms (HS256/HS384/HS512). */
        protected string $secret,

        /** Signing algorithm (e.g. HS256). */
        protected string $algorithm,

        /** Access-token TTL in minutes. */
        protected int $accessTtlMinutes,

    ) {}

    /**
     * Encode an access-token payload for the given context.
     *
     * The payload carries `sub` (identity id), `pid` (principal id),
     * `did` (device id or null), `iat` (issued-at) and `exp` (expiry)
     * claims. Expiry is derived from `accessTtlMinutes`.
     */
    public function issueAccessToken(Identity $identity, Principal $principal, ?Device $device): string
    {
        $now = Carbon::now()->getTimestamp();

        $payload = [
            'sub' => $identity->getAuthIdentifier(),
            'pid' => $principal->getPrincipalIdentifier(),
            'did' => $device?->getDeviceIdentifier(),
            'iat' => $now,
            'exp' => $now + ($this->accessTtlMinutes * 60),
        ];

        return JWT::encode($payload, $this->secret, $this->algorithm);
    }

    /**
     * Encode a refresh-token payload bound to a specific device's
     * plaintext refresh key.
     *
     * The payload carries `did` (device id), `rk` (plaintext refresh
     * key, which the guard verifies against the hashed column on the
     * device record) and `iat` (issued-at). Refresh tokens intentionally
     * carry no `exp` claim: their lifetime is bounded by the
     * `refresh_ttl_minutes` check performed by the guard against the
     * device's `last_logged_in_at` timestamp.
     */
    public function issueRefreshToken(Device $device, string $refreshKeyPlaintext): string
    {
        $now = Carbon::now()->getTimestamp();

        $payload = [
            'did' => $device->getDeviceIdentifier(),
            'rk'  => $refreshKeyPlaintext,
            'iat' => $now,
        ];

        return JWT::encode($payload, $this->secret, $this->algorithm);
    }

    /**
     * Decode and verify a token, returning its claims as an associative array.
     *
     * Returns `null` for any decode, signature, or expiry failure so
     * callers can treat parse as a total function.
     *
     * @return array<string, mixed>|null
     */
    public function parse(string $token): ?array
    {
        try {
            $decoded = JWT::decode($token, new Key($this->secret, $this->algorithm));
        } catch (Throwable) {
            return null;
        }

        return (array) $decoded;
    }

    /**
     * Decode a token without enforcing expiry — used by `JwtGuard::refresh()`.
     *
     * Returns the decoded claims even if the token's `exp` claim has passed,
     * but still rejects signature failures and malformed tokens.
     *
     * @return array<string, mixed>|null
     */
    public function parseAllowingExpired(string $token): ?array
    {
        try {
            $decoded = JWT::decode($token, new Key($this->secret, $this->algorithm));
        } catch (ExpiredException) {

            // The library rejected the token solely because its `exp`
            // claim has passed; fall back to a manual decode so the
            // guard can still read the `did`/`rk` claims during refresh.
            return $this->decodeIgnoringExpiry($token);
        } catch (Throwable) {
            return null;
        }

        return (array) $decoded;
    }

    /**
     * Decode a token's payload segment without verifying its signature
     * or expiry. Only reachable from `parseAllowingExpired()` after the
     * library has already rejected the token because of its `exp` claim.
     *
     * @return array<string, mixed>|null
     */
    private function decodeIgnoringExpiry(string $token): ?array
    {
        $segments = explode('.', $token);

        if (count($segments) !== 3) {
            return null;
        }

        $payload = json_decode(JWT::urlsafeB64Decode($segments[1]), true);

        return is_array($payload) ? $payload : null;
    }
}
