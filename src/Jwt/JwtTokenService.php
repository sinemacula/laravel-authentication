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
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\SubjectType;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationClaims;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationSummary;
use SineMacula\Laravel\Authentication\Secrets\Plaintext;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\SessionRecords\SessionDeadlines;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * JWT issue/parse service.
 *
 * Encapsulates `firebase/php-jwt` so the guards do not import it directly.
 * Issues access and refresh tokens, decodes and verifies.
 *
 * - signing material and algorithm live in a `JwtKeyring` that fails closed
 * - kid-based rotation via the active kid header and `kid -> Key` map
 * - the JOSE header's `typ` distinguishes access (`at+jwt`) from refresh
 *   (`refresh+jwt`), and each type's required claims
 *   (`TokenType::requiredClaims()`) must be present on every parse
 * - `client_id` binds every token to the guard (the application) whose service
 *   issued it; a token from another guard is rejected even when the guards
 *   share a key
 * - `iss` and `aud` are required, written on every token and strictly verified
 *   on every parse
 * - an access token's subject type, session claims and tenant must keep the
 *   profile's shape (`TokenProfile::accessFailure()`)
 * - configurable clock skew via `leewaySeconds` on every verification
 * - token lifetimes from the guard's `TokenLifetimes`; a token for a session
 *   mirrors the session and is never issued for one that has ended
 * - every token it issues is a `Secret`, revealed only where it is sent, and no
 *   token or claim that is a secret ever reaches its logger
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
     * @param  string  $issuer
     * @param  string  $audience
     * @param  ?\Psr\Log\LoggerInterface  $logger
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** Signing and verification material, keyed by kid. */
        private JwtKeyring $keyring,

        /** Guard (the application) the service issues for; written to and required in `client_id`. */
        private string $guard,

        /** Token and session lifetimes the issued `exp` claims follow. */
        private TokenLifetimes $lifetimes,

        /** Clock-skew tolerance applied to every `exp`/`iat` check. */
        private int $leewaySeconds,

        /** The `iss` every token carries; rejects tokens with a different issuer. */
        private string $issuer,

        /** The `aud` every token carries; rejects tokens with a different audience. */
        private string $audience,

        // Optional PSR-3 logger for parse-failure debug traces; defaults to
        // NullLogger.
        ?LoggerInterface $logger = null,
    ) {
        if ($guard === '') {
            throw new \InvalidArgumentException('JWT token service requires a non-empty guard name.');
        }

        if ($issuer === '' || $audience === '') {
            throw new \InvalidArgumentException('JWT token service requires a non-empty issuer and audience.');
        }

        $this->logger = $logger ?? new NullLogger;
    }

    /**
     * The token and session lifetimes this service issues with, which code that
     * creates a session uses to stamp the session's deadlines.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes
     */
    public function lifetimes(): TokenLifetimes
    {
        return $this->lifetimes;
    }

    /**
     * Encode an access-token payload for the given context.
     *
     * The token expires after the guard's access lifetime, and never after the
     * end of the session when a session is given: the earlier of its idle and
     * absolute deadlines, from which the bearer path rejects the token anyway.
     * An idle lifetime shorter than the access lifetime therefore shortens the
     * token to match. `$issuedAt` (default now, cut to the whole second) sets
     * `iat` and the start of the lifetime, so a caller that has just judged the
     * session at a given time issues at that same time. Issuing reads nothing
     * from the principal beyond its identifier and, for a token without a
     * session given a tenant, its tenant (`getTenant()`), to check the tenant
     * is its own.
     *
     * The token's subject type is `person`. `$tenant` is the active tenant the
     * caller's admission found, written to `tenant_id`: for a token of a
     * session, the tenant the session acts in, which the bearer path checks on
     * every request against the session; without a session, the principal's
     * own, since a principal acts in another tenant only through a session. A
     * token for a session carries the session's latest authentication time in
     * `auth_time` (never after the issue time: an authentication another server
     * recorded with its clock ahead is carried as the issue time) and its
     * authentication method references in `amr`, both derived from the session
     * when the token is issued.
     *
     * Refuses to issue a token that `parse()` would reject or that would lose
     * part of its context: the identity and principal, the tenant when one is
     * given, and the session when one is given, must each have an identifier
     * that can be written into its claim (a saved model's scalar key). With a
     * session, the tenant given must be the one the session records, by
     * identifier, or none for a session that records none; without one, it must
     * be the principal's own (a principal whose tenant cannot be loaded throws
     * the `TenantUnavailableException` its `getTenant()` does). Refuses, too, a
     * session that has ended or that has no idle deadline, and a non-human
     * identity: a machine gets tokens only from a client credentials exchange.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\Carbon\CarbonInterface  $issuedAt
     * @return \SineMacula\Laravel\Authentication\Secrets\Secret
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     */
    public function issueAccessToken(Identity $identity, Principal $principal, ?Tenant $tenant, ?Session $session, ?CarbonInterface $issuedAt = null): Secret
    {
        MachineTokens::refuseSession($identity instanceof MachineIdentity);

        return $this->issueAccess($identity, $principal, $tenant, $session, $issuedAt, null, []);
    }

    /**
     * Encode the access token a client credentials exchange hands a non-human
     * identity, acting as the principal, for the API key it was exchanged for:
     * the client (the identity) in `sub` with the subject type `machine`, no
     * session and no refresh, the key's id in `cid` and the granted scopes,
     * space-separated, in `scope` (`""` for none), and the tenant the
     * exchange's admission loaded in `tenant_id`, which must be the one the
     * principal's `getTenant()` returns, by identifier, since a principal acts
     * only within its own tenant. The token lives the guard's access lifetime,
     * never past `$notAfter` (the key's expiry); `$issuedAt` (default now, cut
     * to the whole second) sets `iat`. Every other claim is an access token's,
     * so the bearer path admits the identity and principal as it would any
     * other, and then holds the token to its key.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\MachineIdentity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  string  $credentialId
     * @param  list<string>  $scopes
     * @param  ?\Carbon\CarbonInterface  $notAfter
     * @param  ?\Carbon\CarbonInterface  $issuedAt
     * @return \SineMacula\Laravel\Authentication\Secrets\Secret
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     */
    public function issueClientAccessToken(
        MachineIdentity $identity,
        Principal $principal,
        ?Tenant $tenant,
        #[\SensitiveParameter]
        string $credentialId,
        array $scopes,
        ?CarbonInterface $notAfter = null,
        ?CarbonInterface $issuedAt = null,
    ): Secret {
        return $this->issueAccess($identity, $principal, $tenant, null, $issuedAt, $notAfter, MachineTokens::claims($credentialId, $scopes));
    }

    /**
     * Encode a refresh-token payload bound to a specific session.
     *
     * The token expires at the session's idle deadline, and never after its
     * absolute deadline when it has one: the session row is the source of truth
     * for how long the session lasts, and the token mirrors it. `$issuedAt`
     * (default now, cut to the whole second) sets `iat`.
     *
     * The caller MUST hash the supplied plaintext `$rotationId` before
     * persisting it on the session row. Refuses to issue a token that `parse()`
     * would reject or that would lose its principal: the session, and the
     * principal when one is given, must each have an identifier that can be
     * written into its claim, and the rotation id must not be empty. Refuses,
     * too, a session that has ended or that has no idle deadline, and a session
     * a non-human identity owns, or a non-human principal: a machine has no
     * session and no refresh.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  string  $rotationId
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\Carbon\CarbonInterface  $issuedAt
     * @return \SineMacula\Laravel\Authentication\Secrets\Secret
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function issueRefreshToken(Session $session, #[\SensitiveParameter] string $rotationId, ?Principal $principal = null, ?CarbonInterface $issuedAt = null): Secret
    {
        $machineOwned = $session instanceof EloquentSession && $session instanceof Model && SessionOwnership::isMachineOwned($session);

        MachineTokens::refuseSession($principal instanceof MachineIdentity || $machineOwned);

        $issuedAt = TokenLifetimes::issueTime($issuedAt);

        $payload = $this->baseClaims();

        $payload[Claims::SESSION_ID->value] = $this->requireClaimValue(Claims::SESSION_ID, $session->getSessionIdentifier());

        if ($principal !== null) {
            $payload[Claims::PRINCIPAL->value] = $this->requireClaimValue(Claims::PRINCIPAL, $principal->getPrincipalIdentifier());
        }

        $payload[Claims::JWT_ID->value]     = $this->requireClaimValue(Claims::JWT_ID, $rotationId);
        $payload[Claims::ISSUED_AT->value]  = $issuedAt->getTimestamp();
        $payload[Claims::EXPIRES_AT->value] = $this->sessionEnd($session, $issuedAt)->getTimestamp();

        return $this->encode($payload, TokenType::REFRESH);
    }

    /**
     * Decode and verify a token, returning claims as an array.
     *
     * Returns `null` on any failure so callers can treat parse as a total
     * function. A token whose header `typ` is missing or names no known type is
     * always rejected, and when `$expectedType` is supplied, so is one whose
     * header names the other type, to prevent a refresh token being presented
     * as an access token (and vice versa). A token whose `client_id` does not
     * name this service's guard, or whose `iss` or `aud` is not this service's
     * (an `aud` that is an array included), is always rejected, as is one
     * missing any claim its type requires, and an access token that breaks the
     * profile's shape (see `TokenProfile::accessFailure()`). The token is the
     * one a request carried or one this service issued.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $token
     * @param  ?\SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $expectedType
     * @return ?array<string, mixed>
     */
    public function parse(#[\SensitiveParameter] Secret|string $token, ?TokenType $expectedType = null): ?array
    {
        return $this->verifiedClaims(Plaintext::of($token), $expectedType, false);
    }

    /**
     * Decode and verify a refresh token a client offers as proof that it holds
     * a session, accepting one that has expired.
     *
     * Every check `parse($token, TokenType::REFRESH)` makes applies (the
     * signature and kid, the header `typ`, `client_id`, `iss` and `aud`, the
     * required claims, and an `iat` that is not in the future) except expiry:
     * firebase/php-jwt verifies the signature, kid, algorithm and `iat` before
     * it rejects an expired token, so the header and payload of an expired one
     * are as trustworthy as a live one's. Expiry is not enforced because the
     * usual proof is from a client signing in again after its session ended;
     * the session row decides what the proof is worth. Returns `null` on any
     * other failure.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $token
     * @return ?array<string, mixed>
     */
    public function parseRefreshProof(#[\SensitiveParameter] Secret|string $token): ?array
    {
        return $this->verifiedClaims(Plaintext::of($token), TokenType::REFRESH, true);
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

        [$typ, $payload] = $decoded;

        $claims = $this->normalizeClaims($payload);

        return $this->matchesExpectedClaims($claims, $typ, $expectedType) ? $claims : null;
    }

    /**
     * Encode an access token for the context, with any further claims: its
     * lifetime is the guard's access lifetime, never past the end of the
     * session or, without a session, `$notAfter`, which must be after the issue
     * time. The subject type follows the identity's kind.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\Carbon\CarbonInterface  $issuedAt
     * @param  ?\Carbon\CarbonInterface  $notAfter
     * @param  array<string, string>  $claims
     * @return \SineMacula\Laravel\Authentication\Secrets\Secret
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     */
    private function issueAccess(
        Identity $identity,
        Principal $principal,
        ?Tenant $tenant,
        ?Session $session,
        ?CarbonInterface $issuedAt,
        ?CarbonInterface $notAfter,
        array $claims,
    ): Secret {
        $issuedAt  = TokenLifetimes::issueTime($issuedAt);
        $ends      = $session === null ? TokenLifetimes::notAfter($notAfter, $issuedAt) : $this->sessionEnd($session, $issuedAt);
        $expiresAt = $this->lifetimes->accessExpiry($issuedAt, $ends);

        $payload = $this->baseClaims();

        $payload[Claims::SUBJECT->value]      = $this->requireClaimValue(Claims::SUBJECT, $identity->getAuthIdentifier());
        $payload[Claims::SUBJECT_TYPE->value] = ($identity instanceof MachineIdentity ? SubjectType::MACHINE : SubjectType::PERSON)->value;
        $payload[Claims::PRINCIPAL->value]    = $this->requireClaimValue(Claims::PRINCIPAL, $principal->getPrincipalIdentifier());

        $tenantId = $tenant === null ? null : $this->requireClaimValue(Claims::TENANT_ID, $tenant->getTenantIdentifier());

        if ($tenantId !== null) {
            $payload[Claims::TENANT_ID->value] = $session === null ? TokenProfile::ownTenant($principal, $tenantId) : $tenantId;
        }

        if ($session !== null) {
            TokenProfile::sessionTenant($session, $tenantId);
        }

        if ($session !== null) {
            $payload = [...$payload, ...$this->sessionClaims($session, $issuedAt)];
        }

        $payload[Claims::JWT_ID->value]     = RefreshTokenHasher::generate();
        $payload[Claims::ISSUED_AT->value]  = $issuedAt->getTimestamp();
        $payload[Claims::EXPIRES_AT->value] = $expiresAt->getTimestamp();

        return $this->encode([...$payload, ...$claims], TokenType::ACCESS);
    }

    /**
     * The claims an access token for the session carries: the session, the time
     * of its latest authentication, never after the issue time, and its
     * authentication method references, derived inside
     * `WriteConnection::during()` for the session, so they are read from the
     * writer rather than a lagging replica.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \Carbon\CarbonImmutable  $issuedAt
     * @return array<string, mixed>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function sessionClaims(Session $session, CarbonImmutable $issuedAt): array
    {
        $sessionId = $this->requireClaimValue(Claims::SESSION_ID, $session->getSessionIdentifier());
        $summary   = WriteConnection::during($session, static fn (): AuthenticationSummary => AuthenticationClaims::forSession($session));

        return [
            Claims::SESSION_ID->value             => $sessionId,
            Claims::AUTH_TIME->value              => min($summary->authenticatedAt->getTimestamp(), $issuedAt->getTimestamp()),
            Claims::AUTHENTICATION_METHODS->value => $summary->methods,
        ];
    }

    /**
     * Return when the session ends, the earlier of its idle and absolute
     * deadlines (the idle one alone when it has no absolute one), refusing to
     * issue for a session that has ended at the issue time or that has no idle
     * deadline: a token for it could never be used, and must not be able to
     * extend a session that is over.
     *
     * The deadlines are read inside `WriteConnection::during()` for the
     * session, so a session that derives one from another table caps its tokens
     * at the writer's deadline, not a lagging replica's.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \Carbon\CarbonInterface  $issuedAt
     * @return \Carbon\CarbonImmutable
     *
     * @throws \InvalidArgumentException
     */
    private function sessionEnd(Session $session, CarbonInterface $issuedAt): CarbonImmutable
    {
        return WriteConnection::during($session, static fn (): ?CarbonImmutable => SessionDeadlines::liveEnd($session, $issuedAt))
            ?? throw new \InvalidArgumentException('Cannot issue a token for a session that has ended or that has no idle deadline.');
    }

    /**
     * Build the claims every token starts with: `iss`, `aud` and `client_id`.
     *
     * @return array<string, mixed>
     */
    private function baseClaims(): array
    {
        return [
            Claims::ISSUER->value    => $this->issuer,
            Claims::AUDIENCE->value  => $this->audience,
            Claims::CLIENT_ID->value => $this->guard,
        ];
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
     * Encode the claim payload as a JWT of the type with the keyring's active
     * key, signing under that key's algorithm and embedding its kid and the
     * type in the header, and hold it as a secret from the moment it exists.
     *
     * @param  array<string, mixed>  $payload
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @return \SineMacula\Laravel\Authentication\Secrets\Secret
     */
    private function encode(array $payload, TokenType $type): Secret
    {
        return new Secret(JWT::encode(
            $payload,
            $this->keyring->activeKey()->getKeyMaterial(),
            $this->keyring->activeKey()->getAlgorithm(),
            $this->keyring->activeKid(),
            ['typ' => $type->value],
        ));
    }

    /**
     * Run firebase/php-jwt with the configured leeway. Returns the header's
     * `typ` and the decoded payload, or `null` on any decode, signature or
     * expiry failure; with `$acceptExpired`, the verified header type and
     * payload of a token whose only fault is that it has expired. php-jwt fills
     * the header argument only when it is not `null`, and before it checks the
     * signature, so the header is trusted only once `decode()` returns or
     * throws `ExpiredException`, which it throws only after the signature, kid,
     * algorithm and `iat` have been verified.
     *
     * `firebase/php-jwt` exposes leeway only via the public static
     * `JWT::$leeway`. The previous value is captured and restored around the
     * decode so a consumer-configured leeway survives. Persistent-worker
     * runtimes (Octane, Swoole, ReactPHP) must rely on their own
     * request-isolation model; this code does not lock.
     *
     * @param  string  $token
     * @param  bool  $acceptExpired
     * @return ?array{0: mixed, 1: object}
     */
    private function decodeToken(#[\SensitiveParameter] string $token, bool $acceptExpired): ?array
    {
        $previousLeeway = JWT::$leeway;
        $header         = new \stdClass;

        try {

            JWT::$leeway = $this->leewaySeconds;

            $payload = JWT::decode($token, $this->keyring->verificationKeys(), $header);

            return [$header->typ ?? null, $payload];
        } catch (\Throwable $e) {

            if ($acceptExpired && $e instanceof ExpiredException) {
                return [$header->typ ?? null, $e->getPayload()];
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
    private function normalizeClaims(object $decoded): array
    {
        return array_filter((array) $decoded, fn ($key) => is_string($key), ARRAY_FILTER_USE_KEY);
    }

    /**
     * Verify the header type against the expected one, the guard, issuer and
     * audience against this service's, then that every claim the token's type
     * requires is present and, for an access token, that it keeps the profile's
     * shape.
     *
     * @param  array<string, mixed>  $claims
     * @param  mixed  $typ
     * @param  ?\SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $expectedType
     * @return bool
     */
    private function matchesExpectedClaims(array $claims, mixed $typ, ?TokenType $expectedType): bool
    {
        $type    = TokenProfile::headerType($typ);
        $failure = match (true) {
            $type === null || ($expectedType !== null && $type !== $expectedType) => [
                'message' => 'JWT typ header mismatch',
                'context' => ['expected' => $expectedType?->value, 'received' => $typ],
            ],
            default => $this->firstClaimMismatch($claims) ?? $this->firstMissingClaim($claims, $type) ?? $this->shapeFailure($claims, $type),
        };

        if ($failure === null) {
            return true;
        }

        $this->logger->debug($failure['message'], $failure['context']);

        return false;
    }

    /**
     * Locate the first claim the token's type requires that is absent, `null`,
     * or empty, or return `null` when all are present.
     *
     * @param  array<string, mixed>  $claims
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @return array{message: string, context: array<string, mixed>}|null
     */
    private function firstMissingClaim(array $claims, TokenType $type): ?array
    {
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
     * Locate why the token breaks the profile's shape, or return `null` when it
     * keeps it (see `TokenProfile::accessFailure()` and
     * `TokenProfile::refreshFailure()`).
     *
     * @param  array<string, mixed>  $claims
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\TokenType  $type
     * @return array{message: string, context: array<string, mixed>}|null
     */
    private function shapeFailure(array $claims, TokenType $type): ?array
    {
        $message = $type === TokenType::ACCESS
            ? TokenProfile::accessFailure($claims, $this->leewaySeconds)
            : TokenProfile::refreshFailure($claims);

        return $message === null ? null : ['message' => $message, 'context' => ['typ' => $type->value]];
    }

    /**
     * Locate the first guard/issuer/audience mismatch, or return `null` when
     * every check passes. Each is compared strictly, so a token missing one, or
     * with an `aud` that is an array, is rejected.
     *
     * @param  array<string, mixed>  $claims
     * @return array{message: string, context: array{expected: string, received: mixed}}|null
     */
    private function firstClaimMismatch(array $claims): ?array
    {
        $checks = [
            [Claims::CLIENT_ID->value, $this->guard, 'JWT client_id mismatch'],
            [Claims::ISSUER->value, $this->issuer, 'JWT issuer mismatch'],
            [Claims::AUDIENCE->value, $this->audience, 'JWT audience mismatch'],
        ];

        foreach ($checks as [$claimKey, $expected, $message]) {
            if (($claims[$claimKey] ?? null) !== $expected) {
                return [
                    'message' => $message,
                    'context' => ['expected' => $expected, 'received' => $claims[$claimKey] ?? null],
                ];
            }
        }

        return null;
    }
}
