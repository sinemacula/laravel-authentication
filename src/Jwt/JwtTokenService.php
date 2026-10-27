<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;

/**
 * JWT issue/parse service.
 *
 * Encapsulates `firebase/php-jwt` so the guards do not import it directly.
 * Issues access and refresh tokens, decodes and verifies.
 *
 * - signing material and algorithm live in a `JwtKeyring` that fails closed
 * - kid-based rotation via the active kid header and `kid -> Key` map
 * - `typ` claim distinguishes access from refresh, and each type's required
 *   claims (`TokenType::requiredClaims()`) must be present on every parse
 * - `grd` claim binds every token to the guard whose service issued it; a token
 *   from another guard is rejected even when the guards share a key
 * - configurable clock skew via `leewaySeconds` on every verification
 * - optional strict `iss` / `aud` verification
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class JwtTokenService
{
    /** @var \Psr\Log\LoggerInterface PSR-3 logger for parse-failure debug traces. */
    private LoggerInterface $logger;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtKeyring  $keyring
     * @param  string  $guard
     * @param  int  $accessTtlMinutes
     * @param  int  $refreshTtlMinutes
     * @param  int  $leewaySeconds
     * @param  ?string  $issuer
     * @param  ?string  $audience
     * @param  ?\Psr\Log\LoggerInterface  $logger
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** Signing and verification material, keyed by kid. */
        private JwtKeyring $keyring,

        /** Guard the service issues for; written to and required in `grd`. */
        private string $guard,

        /** Access-token lifetime in minutes, written into the `exp` claim. */
        private int $accessTtlMinutes,

        /** Refresh-token lifetime in minutes, written into the `exp` claim. */
        private int $refreshTtlMinutes,

        /** Clock-skew tolerance applied to every `exp`/`iat` check. */
        private int $leewaySeconds = 30,

        /** Optional `iss` claim; rejects tokens with a different issuer. */
        private ?string $issuer = null,

        /** Optional `aud` claim; rejects tokens with a different audience. */
        private ?string $audience = null,

        // Optional PSR-3 logger for parse-failure debug traces; defaults to
        // NullLogger.
        ?LoggerInterface $logger = null,
    ) {
        if ($guard === '') {
            throw new \InvalidArgumentException('JWT token service requires a non-empty guard name.');
        }

        $this->logger = $logger ?? new NullLogger;
    }

    /**
     * Encode an access-token payload for the given context.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return string
     *
     * @throws \Random\RandomException
     */
    public function issueAccessToken(Identity $identity, Principal $principal, ?Device $device): string
    {
        $now = Carbon::now()->getTimestamp();

        $payload = $this->baseClaims($now, $now + ($this->accessTtlMinutes * 60), TokenType::ACCESS);

        $payload[Claims::SUBJECT->value]      = IdentifierCoercion::stringify($identity->getAuthIdentifier());
        $payload[Claims::PRINCIPAL_ID->value] = IdentifierCoercion::stringify($principal->getPrincipalIdentifier());
        $payload[Claims::DEVICE_ID->value]    = $device === null ? null : IdentifierCoercion::stringify($device->getDeviceIdentifier());
        $payload[Claims::JWT_ID->value]       = RefreshTokenHasher::generate();

        return $this->encode($payload);
    }

    /**
     * Encode a refresh-token payload bound to a specific device.
     *
     * The caller MUST hash the supplied plaintext `$rotationId` before
     * persisting it on the device row.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  string  $rotationId
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return string
     */
    public function issueRefreshToken(Device $device, #[\SensitiveParameter] string $rotationId, ?Principal $principal = null): string
    {
        $now = Carbon::now()->getTimestamp();

        $payload = $this->baseClaims($now, $now + ($this->refreshTtlMinutes * 60), TokenType::REFRESH);

        $payload[Claims::DEVICE_ID->value] = IdentifierCoercion::stringify($device->getDeviceIdentifier());
        $payload[Claims::JWT_ID->value]    = $rotationId;

        if ($principal !== null) {
            $payload[Claims::PRINCIPAL_ID->value] = IdentifierCoercion::stringify($principal->getPrincipalIdentifier());
        }

        return $this->encode($payload);
    }

    /**
     * Decode and verify a token, returning claims as an array.
     *
     * Returns `null` on any failure so callers can treat parse as a total
     * function. A token whose `grd` claim does not name this service's guard is
     * always rejected. When `$expectedType` is supplied, tokens whose `typ`
     * claim does not match are rejected to prevent a refresh token being
     * presented as an access token (and vice versa). A token missing any claim
     * its type requires, or whose `typ` is not a known type, is rejected.
     *
     * @param  string  $token
     * @param  ?\SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $expectedType
     * @return ?array<string, mixed>
     */
    public function parse(#[\SensitiveParameter] string $token, ?TokenType $expectedType = null): ?array
    {
        $decoded = $this->decodeToken($token);

        if ($decoded === null) {
            return null;
        }

        $claims = $this->normaliseClaims($decoded);

        return $this->matchesExpectedClaims($claims, $expectedType) ? $claims : null;
    }

    /**
     * Build the base claim set (iat, exp, typ, grd, iss, aud).
     *
     * @param  int  $issuedAt
     * @param  int  $expiresAt
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @return array<string, mixed>
     */
    private function baseClaims(int $issuedAt, int $expiresAt, TokenType $type): array
    {
        $claims = [
            Claims::ISSUED_AT->value  => $issuedAt,
            Claims::EXPIRES_AT->value => $expiresAt,
            Claims::TYPE->value       => $type->value,
            Claims::GUARD->value      => $this->guard,
        ];

        if ($this->issuer !== null) {
            $claims[Claims::ISSUER->value] = $this->issuer;
        }

        if ($this->audience !== null) {
            $claims[Claims::AUDIENCE->value] = $this->audience;
        }

        return $claims;
    }

    /**
     * Encode the claim payload as a JWT with the keyring's active key, signing
     * under that key's algorithm and embedding its kid in the header.
     *
     * @param  array<string, mixed>  $payload
     * @return string
     */
    private function encode(array $payload): string
    {
        return JWT::encode(
            $payload,
            $this->keyring->activeKey()->getKeyMaterial(),
            $this->keyring->activeKey()->getAlgorithm(),
            $this->keyring->activeKid(),
        );
    }

    /**
     * Run firebase/php-jwt with the configured leeway. Returns the decoded
     * payload, or `null` on any decode/signature/expiry failure.
     *
     * `firebase/php-jwt` exposes leeway only via the public static
     * `JWT::$leeway`. The previous value is captured and restored around the
     * decode so a consumer-configured leeway survives. Persistent-worker
     * runtimes (Octane, Swoole, ReactPHP) must rely on their own
     * request-isolation model; this code does not lock.
     *
     * @param  string  $token
     * @return ?\stdClass
     */
    private function decodeToken(#[\SensitiveParameter] string $token): ?\stdClass
    {
        $previousLeeway = JWT::$leeway;

        try {

            JWT::$leeway = $this->leewaySeconds;

            return JWT::decode($token, $this->keyring->verificationKeys());
        } catch (\Throwable $e) {

            $this->logger->debug('JWT decode failed', [
                'exception' => $e::class,
                'reason'    => $e->getMessage(),
            ]);

            return null;
        } finally {
            JWT::$leeway = $previousLeeway;
        }
    }

    /**
     * Convert the decoded payload into a string-keyed array, dropping any
     * numeric keys.
     *
     * @param  \stdClass  $decoded
     * @return array<string, mixed>
     */
    private function normaliseClaims(\stdClass $decoded): array
    {
        return array_filter((array) $decoded, fn ($key) => is_string($key), ARRAY_FILTER_USE_KEY);
    }

    /**
     * Verify guard, issuer, audience, and `typ` against expected values, then
     * that every claim the token's type requires is present.
     *
     * @param  array<string, mixed>  $claims
     * @param  ?\SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $expectedType
     * @return bool
     */
    private function matchesExpectedClaims(array $claims, ?TokenType $expectedType): bool
    {
        $failure = $this->firstClaimMismatch($claims, $expectedType) ?? $this->firstMissingClaim($claims);

        if ($failure === null) {
            return true;
        }

        $this->logger->debug($failure['message'], $failure['context']);

        return false;
    }

    /**
     * Locate the first claim the token's type requires that is absent, `null`,
     * or empty, or return `null` when all are present. A token whose `typ` is
     * not a known type fails here too, since its required claims are unknown.
     *
     * @param  array<string, mixed>  $claims
     * @return array{message: string, context: array<string, mixed>}|null
     */
    private function firstMissingClaim(array $claims): ?array
    {
        $typ  = $claims[Claims::TYPE->value] ?? null;
        $type = is_string($typ) ? TokenType::tryFrom($typ) : null;

        if ($type === null) {
            return [
                'message' => 'JWT typ unknown',
                'context' => ['received' => $typ],
            ];
        }

        foreach ($type->requiredClaims() as $claim) {

            $value = $claims[$claim->value] ?? null;

            if ($value === null || $value === '') {
                return [
                    'message' => 'JWT required claim missing',
                    'context' => ['claim' => $claim->value, 'typ' => $type->value],
                ];
            }
        }

        return null;
    }

    /**
     * Locate the first guard/issuer/audience/`typ` mismatch, or return `null`
     * when every check passes. The guard is always checked, so a token missing
     * `grd` is rejected.
     *
     * @param  array<string, mixed>  $claims
     * @param  ?\SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $expectedType
     * @return array{message: string, context: array{expected: mixed, received: mixed}}|null
     */
    private function firstClaimMismatch(array $claims, ?TokenType $expectedType): ?array
    {
        $checks = [
            [Claims::GUARD->value, $this->guard, 'JWT guard mismatch'],
            [Claims::ISSUER->value, $this->issuer, 'JWT issuer mismatch'],
            [Claims::AUDIENCE->value, $this->audience, 'JWT audience mismatch'],
            [Claims::TYPE->value, $expectedType?->value, 'JWT typ mismatch'],
        ];

        foreach ($checks as [$claimKey, $expected, $message]) {
            if ($expected !== null && ($claims[$claimKey] ?? null) !== $expected) {
                return [
                    'message' => $message,
                    'context' => ['expected' => $expected, 'received' => $claims[$claimKey] ?? null],
                ];
            }
        }

        return null;
    }
}
