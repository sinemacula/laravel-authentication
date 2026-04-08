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

/**
 * JWT issue/parse service.
 *
 * Encapsulates `firebase/php-jwt` so the guards do not import it
 * directly. Single-purpose: issue access tokens, issue refresh tokens,
 * decode and verify tokens.
 *
 * Hardening:
 * - signing material is encapsulated in a `JwtKeyring` value object
 *   that fails closed on empty / unknown / mismatched keys,
 * - supports kid-based key rotation: issue tokens with the active
 *   kid embedded in the JWT header, verify against a `kid → Key` map
 *   so old tokens stay valid until they expire,
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
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class JwtTokenService
{
    /** @var \Psr\Log\LoggerInterface PSR-3 logger used to debug-trace parse failures (defaults to NullLogger). */
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

        // Either a legacy single-secret string (back-compat) or a
        // pre-built `JwtKeyring`. The string form is forwarded to
        // `JwtKeyring::fromSecret()` so the fail-closed empty-secret
        // guard remains in a single place.
        #[\SensitiveParameter] JwtKeyring|string $secretOrKeyring,

        /** Signing algorithm (e.g. HS256). */
        protected string $algorithm,

        /** Access-token TTL in minutes. */
        protected int $accessTtlMinutes,

        /** Refresh-token TTL in minutes. */
        protected int $refreshTtlMinutes,

        /** Clock-skew tolerance in seconds applied on every verification. */
        protected int $leewaySeconds = 30,

        /**
         * Optional `iss` claim embedded in issued tokens and strictly
         * verified on parse.
         */
        protected ?string $issuer = null,

        /**
         * Optional `aud` claim embedded in issued tokens and strictly
         * verified on parse.
         */
        protected ?string $audience = null,

        // Optional PSR-3 logger — when supplied, parse failures are
        // debug-logged with their underlying exception class so
        // consumer error reporters can attribute the failure mode
        // without scraping logs.
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

        $payload = $this->baseClaims($now, $now + ($this->accessTtlMinutes * 60), Claims::TYPE_ACCESS);

        $payload[Claims::SUBJECT]      = IdentifierCoercion::stringify($identity->getAuthIdentifier());
        $payload[Claims::PRINCIPAL_ID] = IdentifierCoercion::stringify($principal->getPrincipalIdentifier());
        $payload[Claims::DEVICE_ID]    = $device === null ? null : IdentifierCoercion::stringify($device->getDeviceIdentifier());
        $payload[Claims::JWT_ID]       = RefreshTokenHasher::generate();

        return $this->encode($payload);
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

        return $this->encode($payload);
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
     * Encode the supplied claim payload as a JWT, embedding the
     * keyring's active kid in the header when kid mode is active.
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
     * Run the firebase/php-jwt decoder with the configured leeway and
     * return the decoded payload object on success, or `null` on any
     * decode/signature/expiry failure.
     *
     * Concurrency note: `firebase/php-jwt` exposes clock-skew tolerance
     * only via the public static property `JWT::$leeway`, and offers no
     * per-call or per-`Key` leeway API. To avoid clobbering a consumer
     * value that may have been set outside this package, we capture the
     * previous leeway before the decode and restore it in the `finally`
     * block (rather than hard-resetting to `0`). This preserves any
     * consumer-configured leeway across our decode window.
     *
     * Known limitation — fiber-based runtimes: in truly concurrent
     * environments that run multiple decodes in the same worker process
     * (Laravel Octane persistent workers, Swoole coroutines, ReactPHP
     * fibers), `JWT::$leeway` remains shared mutable state and a second
     * decode scheduled during our capture/restore window will observe
     * this service's leeway value. The correct long-term fixes are
     * either (a) a per-call leeway API upstream in `firebase/php-jwt`
     * or (b) forking the library. We deliberately do NOT wrap the
     * decode in a mutex: `firebase/php-jwt` has no per-call leeway
     * hook, so any such lock would have to serialise *every* decode in
     * the worker process, which is a throughput regression that is
     * strictly worse than accepting the narrow race window. Consumers
     * running in persistent-worker runtimes should rely on the
     * runtime's request-isolation model (Octane's `OCTANE_RESET`,
     * per-coroutine context) to keep decodes logically serialised
     * within a single request.
     *
     * @param  string  $token
     * @return \stdClass|null
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
     * Locate the first issuer/audience/`typ` claim mismatch against
     * the configured/expected values, or return `null` when every
     * check passes (or is unconfigured).
     *
     * @param  array<string, mixed>  $claims
     * @param  ?string  $expectedType
     * @return array{message: string, expected: mixed, received: mixed}|null
     */
    private function firstClaimMismatch(array $claims, ?string $expectedType): ?array
    {
        $checks = [
            [Claims::ISSUER, $this->issuer, 'JWT issuer mismatch'],
            [Claims::AUDIENCE, $this->audience, 'JWT audience mismatch'],
            [Claims::TYPE, $expectedType, 'JWT typ mismatch'],
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
