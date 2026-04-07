<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * JWT issue/parse service.
 *
 * Encapsulates `firebase/php-jwt` so the guards do not import it
 * directly. Single-purpose: issue access tokens, issue refresh tokens,
 * decode and verify tokens.
 *
 * Hardening:
 * - refuses to construct with an empty secret (fail-closed),
 * - stringifies all identifier claims (`sub`, `pid`, `did`, `jti`) so
 *   the payload conforms to RFC 7519 §4.1.2,
 * - embeds a `typ` claim distinguishing access from refresh tokens so
 *   a refresh token cannot be presented as an access token,
 * - issues refresh tokens with an explicit `exp` claim derived from
 *   `refreshTtlMinutes` (no more "stateless refresh lives forever"),
 * - enforces configurable clock skew (`leewaySeconds`) on every
 *   verification,
 * - optionally embeds and strictly verifies `iss` and `aud` claims.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
final class JwtTokenService
{
    /**
     * Constructor.
     *
     * @param  string  $secret
     * @param  string  $algorithm
     * @param  int  $accessTtlMinutes
     * @param  int  $refreshTtlMinutes
     * @param  int  $leewaySeconds
     * @param  ?string  $issuer
     * @param  ?string  $audience
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    public function __construct(

        /** Shared secret used for HMAC algorithms (HS256/HS384/HS512). */
        #[\SensitiveParameter] protected string $secret,

        /** Signing algorithm (e.g. HS256). */
        protected string $algorithm,

        /** Access-token TTL in minutes. */
        protected int $accessTtlMinutes,

        /** Refresh-token TTL in minutes. */
        protected int $refreshTtlMinutes,

        /** Clock-skew tolerance in seconds applied on every verification. */
        protected int $leewaySeconds = 30,

        /** Optional `iss` claim embedded in issued tokens and strictly verified on parse. */
        protected ?string $issuer = null,

        /** Optional `aud` claim embedded in issued tokens and strictly verified on parse. */
        protected ?string $audience = null,

    ) {
        if ($secret === '') {

            $message = 'JWT secret is empty. Set `laravel-authentication.jwt.secret`'
                . ' (env `AUTHENTICATION_JWT_SECRET`) to a strong random value —'
                . ' an empty secret would silently accept forged tokens.';

            throw new InvalidJwtConfigurationException($message);
        }
    }

    /**
     * Encode an access-token payload for the given context.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return string
     */
    public function issueAccessToken(Identity $identity, Principal $principal, ?Device $device): string
    {
        $now = Carbon::now()->getTimestamp();

        $payload = $this->baseClaims($now, $now + ($this->accessTtlMinutes * 60), Claims::TYPE_ACCESS);

        $payload[Claims::SUBJECT]      = IdentifierCoercion::stringify($identity->getAuthIdentifier());
        $payload[Claims::PRINCIPAL_ID] = IdentifierCoercion::stringify($principal->getPrincipalIdentifier());
        $payload[Claims::DEVICE_ID]    = $device === null ? null : IdentifierCoercion::stringify($device->getDeviceIdentifier());

        return JWT::encode($payload, $this->secret, $this->algorithm);
    }

    /**
     * Encode a refresh-token payload bound to a specific device.
     *
     * The token carries `did` (device id), `jti` (opaque rotation
     * identifier the guard verifies against the hashed column on the
     * device record), `typ = refresh`, `iat`, `exp` (derived from
     * `refreshTtlMinutes`), and the optional `iss`/`aud` claims. The
     * caller MUST hash the supplied plaintext `$rotationId` before
     * persisting it on the device row.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  string  $rotationId
     * @return string
     */
    public function issueRefreshToken(Device $device, #[\SensitiveParameter] string $rotationId): string
    {
        $now = Carbon::now()->getTimestamp();

        $payload = $this->baseClaims($now, $now + ($this->refreshTtlMinutes * 60), Claims::TYPE_REFRESH);

        $payload[Claims::DEVICE_ID] = IdentifierCoercion::stringify($device->getDeviceIdentifier());
        $payload[Claims::JWT_ID]    = $rotationId;

        return JWT::encode($payload, $this->secret, $this->algorithm);
    }

    /**
     * Decode and verify a token, returning its claims as an associative array.
     *
     * Returns `null` for any decode, signature, expiry, issuer, or
     * audience failure so callers can treat parse as a total function.
     * When `$expectedType` is supplied, tokens whose `typ` claim does
     * not match are rejected — this prevents a refresh token from
     * being presented as an access token (and vice versa).
     *
     * @param  string  $token
     * @param  ?string  $expectedType
     * @return array<string, mixed>|null
     */
    public function parse(#[\SensitiveParameter] string $token, ?string $expectedType = null): ?array
    {
        $decoded = $this->decodeToken($token);

        if ($decoded === null) {
            return null;
        }

        $claims = $this->normaliseClaims($decoded);

        return $this->matchesExpectedClaims($claims, $expectedType) ? $claims : null;
    }

    /**
     * Run the firebase/php-jwt decoder with the configured leeway and
     * return the decoded payload object on success, or `null` on any
     * decode/signature/expiry failure.
     *
     * @param  string  $token
     * @return \stdClass|null
     */
    private function decodeToken(#[\SensitiveParameter] string $token): ?\stdClass
    {
        try {
            JWT::$leeway = $this->leewaySeconds;

            return JWT::decode($token, new Key($this->secret, $this->algorithm));
        } catch (\Throwable) {
            return null;
        } finally {
            JWT::$leeway = 0;
        }
    }

    /**
     * Convert the decoded `\stdClass` payload into a string-keyed
     * associative array, dropping any numeric keys.
     *
     * @param  \stdClass  $decoded
     * @return array<string, mixed>
     */
    private function normaliseClaims(\stdClass $decoded): array
    {
        $claims = [];

        foreach ((array) $decoded as $key => $value) {
            if (is_string($key)) {
                $claims[$key] = $value;
            }
        }

        return $claims;
    }

    /**
     * Verify the issuer, audience, and `typ` claims against the
     * configured/expected values. Returns `true` when every check
     * passes (or is unconfigured) and `false` otherwise.
     *
     * @param  array<string, mixed>  $claims
     * @param  ?string  $expectedType
     * @return bool
     */
    private function matchesExpectedClaims(array $claims, ?string $expectedType): bool
    {
        if ($this->issuer !== null && ($claims[Claims::ISSUER] ?? null) !== $this->issuer) {
            return false;
        }

        if ($this->audience !== null && ($claims[Claims::AUDIENCE] ?? null) !== $this->audience) {
            return false;
        }

        return !($expectedType !== null && ($claims[Claims::TYPE] ?? null) !== $expectedType);
    }

    /**
     * Build the base claim set (iat, exp, typ, iss, aud) for an
     * issued token.
     *
     * @param  int  $issuedAt
     * @param  int  $expiresAt
     * @param  string  $type
     * @return array<string, mixed>
     */
    private function baseClaims(int $issuedAt, int $expiresAt, string $type): array
    {
        $claims = [
            Claims::ISSUED_AT  => $issuedAt,
            Claims::EXPIRES_AT => $expiresAt,
            Claims::TYPE       => $type,
        ];

        if ($this->issuer !== null) {
            $claims[Claims::ISSUER] = $this->issuer;
        }

        if ($this->audience !== null) {
            $claims[Claims::AUDIENCE] = $this->audience;
        }

        return $claims;
    }
}
