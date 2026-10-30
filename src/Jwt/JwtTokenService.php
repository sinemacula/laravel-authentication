<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Firebase\JWT\ExpiredException;
use Firebase\JWT\JWT;
use Illuminate\Database\Eloquent\Model;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use SineMacula\Laravel\Authentication\Audience\PrincipalType;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

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
 * - `pty` claim carries the principal's type on access tokens, when it has one
 * - configurable clock skew via `leewaySeconds` on every verification
 * - optional strict `iss` / `aud` verification
 * - token lifetimes from the guard's `TokenLifetimes`, or those it sets for the
 *   principal's type; a token for a device mirrors the device's session and is
 *   never issued for one that has ended
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
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     * @param  int  $leewaySeconds
     * @param  ?string  $issuer
     * @param  ?string  $audience
     * @param  ?\Psr\Log\LoggerInterface  $logger
     * @param  array<string, \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes>  $principalTypeLifetimes
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** Signing and verification material, keyed by kid. */
        private JwtKeyring $keyring,

        /** Guard the service issues for; written to and required in `grd`. */
        private string $guard,

        /** Token and session lifetimes the issued `exp` claims follow. */
        private TokenLifetimes $lifetimes,

        /** Clock-skew tolerance applied to every `exp`/`iat` check. */
        private int $leewaySeconds,

        /** Optional `iss` claim; rejects tokens with a different issuer. */
        private ?string $issuer = null,

        /** Optional `aud` claim; rejects tokens with a different audience. */
        private ?string $audience = null,

        // Optional PSR-3 logger for parse-failure debug traces; defaults to
        // NullLogger.
        ?LoggerInterface $logger = null,

        /** Lifetimes for principals of a type, keyed by type; other principals get the guard's. */
        private array $principalTypeLifetimes = [],
    ) {
        if ($guard === '') {
            throw new \InvalidArgumentException('JWT token service requires a non-empty guard name.');
        }

        $this->logger = $logger ?? new NullLogger;
    }

    /**
     * The token and session lifetimes this service issues with, which code that
     * creates a device uses to stamp the device's deadlines.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes
     */
    public function lifetimes(): TokenLifetimes
    {
        return $this->lifetimes;
    }

    /**
     * The lifetimes for a principal: the guard's `by_principal_type` entry for
     * the principal's type (see `Audience\PrincipalType`) when it has one,
     * otherwise the guard's own, which a `null` principal gets too. A guard
     * without per-type lifetimes never reads the principal's type.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     */
    public function lifetimesFor(?Principal $principal): TokenLifetimes
    {
        if ($principal === null || $this->principalTypeLifetimes === []) {
            return $this->lifetimes;
        }

        return $this->lifetimesOfType(PrincipalType::of($principal));
    }

    /**
     * Encode an access-token payload for the given context.
     *
     * The token expires after the access lifetime for the principal's type (see
     * `lifetimesFor()`), and never after the end of the device's session when a
     * device is given: the earlier of its idle and absolute deadlines, from
     * which the bearer path rejects the token anyway. An idle lifetime shorter
     * than the access lifetime therefore shortens the token to match.
     * `$issuedAt` (default now, cut to the whole second) sets `iat` and the
     * start of the lifetime, so a caller that has just judged the device at a
     * given time issues at that same time.
     *
     * The token carries the principal's type in `pty` when it has one (see
     * `Audience\PrincipalType`), read when the token is issued; a principal
     * without a type issues a token without the claim. Nothing checks the claim
     * on a bearer request: the guard admits a principal's type when it issues
     * and refreshes, and `Auth::type()` reads the principal live.
     *
     * Refuses to issue a token that `parse()` would reject or that would lose
     * part of its context: the identity and principal, and the device when one
     * is given, must each have an identifier that can be written into its claim
     * (a saved model's scalar key). Refuses, too, a device whose session has
     * ended or that has no deadlines, and a non-human identity: a machine gets
     * tokens only from a client credentials exchange.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  ?\Carbon\CarbonInterface  $issuedAt
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     */
    public function issueAccessToken(Identity $identity, Principal $principal, ?Device $device, ?CarbonInterface $issuedAt = null): string
    {
        MachineTokens::refuseSession($identity instanceof MachineIdentity);

        return $this->issueAccess($identity, $principal, $device, $issuedAt, null, []);
    }

    /**
     * Encode the access token a client credentials exchange hands a non-human
     * identity, acting as the principal, for the API key it was exchanged for:
     * no device and no refresh, the key's id in `cid` and the granted scopes,
     * space-separated, in `scope` (`""` for none). The token lives the access
     * lifetime for the principal's type, never past `$notAfter` (the key's
     * expiry); `$issuedAt` (default now, cut to the whole second) sets `iat`.
     * Every other claim is an access token's, so the bearer path admits the
     * identity and principal as it would any other, and then holds the token to
     * its key.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\MachineIdentity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $credentialId
     * @param  list<string>  $scopes
     * @param  ?\Carbon\CarbonInterface  $notAfter
     * @param  ?\Carbon\CarbonInterface  $issuedAt
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     */
    public function issueClientAccessToken(
        MachineIdentity $identity,
        Principal $principal,
        #[\SensitiveParameter]
        string $credentialId,
        array $scopes,
        ?CarbonInterface $notAfter = null,
        ?CarbonInterface $issuedAt = null,
    ): string {
        return $this->issueAccess($identity, $principal, null, $issuedAt, $notAfter, MachineTokens::claims($credentialId, $scopes));
    }

    /**
     * Encode a refresh-token payload bound to a specific device.
     *
     * The token expires at the device's idle deadline, and never after its
     * absolute deadline: the device row is the source of truth for how long the
     * session lasts, and the token mirrors it. `$issuedAt` (default now, cut to
     * the whole second) sets `iat`.
     *
     * The caller MUST hash the supplied plaintext `$rotationId` before
     * persisting it on the device row. Refuses to issue a token that `parse()`
     * would reject or that would lose its principal: the device, and the
     * principal when one is given, must each have an identifier that can be
     * written into its claim, and the rotation id must not be empty. Refuses,
     * too, a device whose session has ended or that has no deadlines, and a
     * device a non-human identity owns, or a non-human principal: a machine has
     * no device and no refresh.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  string  $rotationId
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\Carbon\CarbonInterface  $issuedAt
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function issueRefreshToken(Device $device, #[\SensitiveParameter] string $rotationId, ?Principal $principal = null, ?CarbonInterface $issuedAt = null): string
    {
        $machineOwned = $device instanceof EloquentDevice && $device instanceof Model && DeviceOwnership::isMachineOwned($device);

        MachineTokens::refuseSession($principal instanceof MachineIdentity || $machineOwned);

        $issuedAt = TokenLifetimes::issueTime($issuedAt);

        $payload = $this->baseClaims($issuedAt, $this->sessionEnd($device, $issuedAt)->getTimestamp(), TokenType::REFRESH);

        $payload[Claims::DEVICE_ID->value] = $this->requireClaimValue(Claims::DEVICE_ID, $device->getDeviceIdentifier());
        $payload[Claims::JWT_ID->value]    = $this->requireClaimValue(Claims::JWT_ID, $rotationId);

        if ($principal !== null) {
            $payload[Claims::PRINCIPAL_ID->value] = $this->requireClaimValue(Claims::PRINCIPAL_ID, $principal->getPrincipalIdentifier());
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
        return $this->verifiedClaims($token, $expectedType, false);
    }

    /**
     * Decode and verify a refresh token a client offers as proof that it holds
     * a device's session, accepting one that has expired.
     *
     * Every check `parse($token, TokenType::REFRESH)` makes applies (the
     * signature and kid, `grd`, `iss` and `aud`, `typ`, the required claims,
     * and an `iat` that is not in the future) except expiry: firebase/php-jwt
     * verifies all of those before it rejects an expired token, so the payload
     * of an expired one is as trustworthy as a live one's. Expiry is not
     * enforced because the usual proof is from a client signing in again after
     * its session ended; the device row decides what the proof is worth.
     * Returns `null` on any other failure.
     *
     * @param  string  $token
     * @return ?array<string, mixed>
     */
    public function parseRefreshProof(#[\SensitiveParameter] string $token): ?array
    {
        return $this->verifiedClaims($token, TokenType::REFRESH, true);
    }

    /**
     * Decode and verify a token, optionally accepting an expired one, and
     * return its claims when they match this service and the expected type.
     *
     * @param  string  $token
     * @param  ?\SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $expectedType
     * @param  bool  $acceptExpired
     * @return ?array<string, mixed>
     */
    private function verifiedClaims(#[\SensitiveParameter] string $token, ?TokenType $expectedType, bool $acceptExpired): ?array
    {
        $decoded = $this->decodeToken($token, $acceptExpired);

        if ($decoded === null) {
            return null;
        }

        $claims = $this->normaliseClaims($decoded);

        return $this->matchesExpectedClaims($claims, $expectedType) ? $claims : null;
    }

    /**
     * The lifetimes for principals of the type: its own when the guard sets
     * them, otherwise the guard's.
     *
     * @param  ?string  $type
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes
     */
    private function lifetimesOfType(?string $type): TokenLifetimes
    {
        return $type === null ? $this->lifetimes : $this->principalTypeLifetimes[$type] ?? $this->lifetimes;
    }

    /**
     * Encode an access token for the context, with any further claims: its
     * lifetime is the access lifetime for the principal's type, never past the
     * end of the device's session or, without a device, `$notAfter`, which must
     * be after the issue time.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  ?\Carbon\CarbonInterface  $issuedAt
     * @param  ?\Carbon\CarbonInterface  $notAfter
     * @param  array<string, string>  $claims
     * @return string
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     */
    private function issueAccess(Identity $identity, Principal $principal, ?Device $device, ?CarbonInterface $issuedAt, ?CarbonInterface $notAfter, array $claims): string
    {
        $issuedAt  = TokenLifetimes::issueTime($issuedAt);
        $ends      = $device === null ? TokenLifetimes::notAfter($notAfter, $issuedAt) : $this->sessionEnd($device, $issuedAt);
        $type      = PrincipalType::of($principal);
        $expiresAt = $this->lifetimesOfType($type)->accessExpiry($issuedAt, $ends);

        $payload = $this->baseClaims($issuedAt, $expiresAt->getTimestamp(), TokenType::ACCESS);

        $payload[Claims::SUBJECT->value]      = $this->requireClaimValue(Claims::SUBJECT, $identity->getAuthIdentifier());
        $payload[Claims::PRINCIPAL_ID->value] = $this->requireClaimValue(Claims::PRINCIPAL_ID, $principal->getPrincipalIdentifier());
        $payload[Claims::DEVICE_ID->value]    = $device === null ? null : $this->requireClaimValue(Claims::DEVICE_ID, $device->getDeviceIdentifier());
        $payload[Claims::JWT_ID->value]       = RefreshTokenHasher::generate();

        if ($type !== null) {
            $payload[Claims::PRINCIPAL_TYPE->value] = $type;
        }

        return $this->encode(array_merge($payload, $claims));
    }

    /**
     * Return when the device's session ends, the earlier of its idle and
     * absolute deadlines, refusing to issue for a device whose session has
     * ended at the issue time or that has no deadlines: a token for it could
     * never be used, and must not be able to extend a session that is over.
     *
     * The deadlines are read inside `WriteConnection::during()` for the device,
     * so a device that derives one from another table caps its tokens at the
     * writer's deadline, not a lagging replica's.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @param  \Carbon\CarbonInterface  $issuedAt
     * @return \Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    private function sessionEnd(Device $device, CarbonInterface $issuedAt): CarbonImmutable
    {
        [$idle, $absolute] = WriteConnection::during($device, static fn (): ?array => TokenLifetimes::liveDeadlines($device, $issuedAt))
            ?? throw new \InvalidArgumentException('Cannot issue a token for a device whose session has ended or that has no idle and absolute deadlines.');

        return CarbonImmutable::createFromTimestamp(min($idle->getTimestamp(), $absolute->getTimestamp()));
    }

    /**
     * Build the base claim set (iat, exp, typ, grd, iss, aud).
     *
     * @param  \Carbon\CarbonInterface  $issuedAt
     * @param  int  $expiresAt
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @return array<string, mixed>
     */
    private function baseClaims(CarbonInterface $issuedAt, int $expiresAt, TokenType $type): array
    {
        $claims = [
            Claims::ISSUED_AT->value  => $issuedAt->getTimestamp(),
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
     * Stringify the value of a claim the token cannot do without, throwing
     * instead of issuing a token whose claim would be missing: `null` (an
     * unsaved model's identifier, or one that is not a scalar) and the empty
     * string both read as missing to `parse()`.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\Claims  $claim
     * @param  mixed  $value
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function requireClaimValue(Claims $claim, #[\SensitiveParameter] mixed $value): string
    {
        $stringified = IdentifierCoercion::stringify($value);

        if ($stringified === null || $stringified === '') {

            $message = sprintf(
                'Cannot issue a token without its `%s` claim: the identifier is null (is the model saved?), empty, or not a scalar.',
                $claim->value,
            );

            throw new \InvalidArgumentException($message);
        }

        return $stringified;
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
     * payload, or `null` on any decode/signature/expiry failure; with
     * `$acceptExpired`, the verified payload of a token whose only fault is
     * that it has expired.
     *
     * `firebase/php-jwt` exposes leeway only via the public static
     * `JWT::$leeway`. The previous value is captured and restored around the
     * decode so a consumer-configured leeway survives. Persistent-worker
     * runtimes (Octane, Swoole, ReactPHP) must rely on their own
     * request-isolation model; this code does not lock.
     *
     * @param  string  $token
     * @param  bool  $acceptExpired
     * @return ?object
     */
    private function decodeToken(#[\SensitiveParameter] string $token, bool $acceptExpired): ?object
    {
        $previousLeeway = JWT::$leeway;

        try {

            JWT::$leeway = $this->leewaySeconds;

            return JWT::decode($token, $this->keyring->verificationKeys());
        } catch (\Throwable $e) {

            // php-jwt checks the signature, kid, algorithm and iat before it
            // rejects an expired token, so this payload is verified.
            if ($acceptExpired && $e instanceof ExpiredException) {
                return $e->getPayload();
            }

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
     * @param  object  $decoded
     * @return array<string, mixed>
     */
    private function normaliseClaims(object $decoded): array
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
        $failure = $this->firstClaimMismatch($claims, $expectedType) ?? $this->firstMissingClaim($claims) ?? (MachineTokens::credential($claims) === false ? [
            'message' => 'JWT credential claims malformed',
            'context' => ['claims' => [Claims::CREDENTIAL_ID->value, Claims::SCOPE->value, Claims::DEVICE_ID->value]],
        ] : null);

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
