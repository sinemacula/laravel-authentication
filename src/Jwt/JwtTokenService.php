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
 * - signing material lives in a `JwtKeyring` that fails closed
 * - kid-based rotation via the active kid header and `kid -> Key` map
 * - `typ` claim distinguishes access from refresh
 * - configurable clock skew via `leewaySeconds` on every verification
 * - optional strict `iss` / `aud` verification
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class JwtTokenService
{
    /** @var \Psr\Log\LoggerInterface PSR-3 logger for parse-failure debug traces. */
    private LoggerInterface $logger;

    /** @var \SineMacula\Laravel\Authentication\Jwt\JwtKeyring Signing / verification material. */
    private JwtKeyring $keyring;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\JwtKeyring|string  $secretOrKeyring
     * @param  string  $algorithm
     * @param  int  $accessTtlMinutes
     * @param  int  $refreshTtlMinutes
     * @param  int  $leewaySeconds
     * @param  ?string  $issuer
     * @param  ?string  $audience
     * @param  ?\Psr\Log\LoggerInterface  $logger
     *
     * @throws \SineMacula\Laravel\Authentication\Jwt\InvalidJwtConfigurationException
     */
    public function __construct(

        // Pre-built keyring, or a single HMAC secret to wrap in a one-kid keyring.
        #[\SensitiveParameter] JwtKeyring|string $secretOrKeyring,

        /** JWS signing algorithm (e.g. `HS256`, `RS256`). */
        private string $algorithm,

        /** Access-token lifetime in minutes, written into the `exp` claim. */
        private int $accessTtlMinutes,

        /** Refresh-token lifetime in minutes, written into the `exp` claim. */
        private int $refreshTtlMinutes,

        /** Clock-skew tolerance in seconds applied to every `exp` / `iat` check. */
        private int $leewaySeconds = 30,

        /** Optional `iss` claim; when set, parse() rejects tokens whose issuer differs. */
        private ?string $issuer = null,

        /** Optional `aud` claim; when set, parse() rejects tokens whose audience differs. */
        private ?string $audience = null,

        // Optional PSR-3 logger for parse-failure debug traces; defaults to NullLogger.
        ?LoggerInterface $logger = null,

    ) {
        $this->keyring = is_string($secretOrKeyring)
            ? JwtKeyring::fromSecret($secretOrKeyring, $algorithm)
            : $secretOrKeyring;

        $this->logger = $logger ?? new NullLogger;
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
     * @return string
     */
    public function issueRefreshToken(Device $device, #[\SensitiveParameter] string $rotationId): string
    {
        $now = Carbon::now()->getTimestamp();

        $payload = $this->baseClaims($now, $now + ($this->refreshTtlMinutes * 60), TokenType::REFRESH);

        $payload[Claims::DEVICE_ID->value] = IdentifierCoercion::stringify($device->getDeviceIdentifier());
        $payload[Claims::JWT_ID->value]    = $rotationId;

        return $this->encode($payload);
    }

    /**
     * Decode and verify a token, returning claims as an array.
     *
     * Returns `null` on any failure so callers can treat parse as a total
     * function. When `$expectedType` is supplied, tokens whose `typ` claim does
     * not match are rejected to prevent a refresh token being presented as an
     * access token (and vice versa).
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
     * Build the base claim set (iat, exp, typ, iss, aud).
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
     * Encode the claim payload as a JWT, embedding the keyring's active kid in
     * the header when kid mode is active.
     *
     * @param  array<string, mixed>  $payload
     * @return string
     */
    private function encode(array $payload): string
    {
        return JWT::encode(
            $payload,
            $this->keyring->activeKey()->getKeyMaterial(),
            $this->algorithm,
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
        $claims = [];

        foreach ((array) $decoded as $key => $value) {
            if (is_string($key)) {
                $claims[$key] = $value;
            }
        }

        return $claims;
    }

    /**
     * Verify issuer, audience, and `typ` against expected values.
     *
     * @param  array<string, mixed>  $claims
     * @param  ?\SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $expectedType
     * @return bool
     */
    private function matchesExpectedClaims(array $claims, ?TokenType $expectedType): bool
    {
        $mismatch = $this->firstClaimMismatch($claims, $expectedType);

        if ($mismatch === null) {
            return true;
        }

        $this->logger->debug($mismatch['message'], [
            'expected' => $mismatch['expected'],
            'received' => $mismatch['received'],
        ]);

        return false;
    }

    /**
     * Locate the first issuer/audience/`typ` mismatch, or return `null` when
     * every check passes.
     *
     * @param  array<string, mixed>  $claims
     * @param  ?\SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $expectedType
     * @return array{message: string, expected: mixed, received: mixed}|null
     */
    private function firstClaimMismatch(array $claims, ?TokenType $expectedType): ?array
    {
        $checks = [
            [Claims::ISSUER->value, $this->issuer, 'JWT issuer mismatch'],
            [Claims::AUDIENCE->value, $this->audience, 'JWT audience mismatch'],
            [Claims::TYPE->value, $expectedType?->value, 'JWT typ mismatch'],
        ];

        foreach ($checks as [$claimKey, $expected, $message]) {
            if ($expected !== null && ($claims[$claimKey] ?? null) !== $expected) {
                return [
                    'message'  => $message,
                    'expected' => $expected,
                    'received' => $claims[$claimKey] ?? null,
                ];
            }
        }

        return null;
    }
}
