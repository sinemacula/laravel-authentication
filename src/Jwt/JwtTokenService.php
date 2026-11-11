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
use SineMacula\Laravel\Authentication\SessionRecords\IssuanceGuard;
use SineMacula\Laravel\Authentication\SessionRecords\SessionDeadlines;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\SessionRecords\SessionOwnership;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Issues and verifies the package's access and refresh tokens.
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

        // PSR-3 logger for parse-failure debug traces.
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
     * The token and session lifetimes this service issues with.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes
     */
    public function lifetimes(): TokenLifetimes
    {
        return $this->lifetimes;
    }

    /**
     * Encode an access token for the given context, never outliving its
     * session.
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
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     * @throws \Throwable
     */
    public function issueAccessToken(Identity $identity, Principal $principal, ?Tenant $tenant, ?Session $session, ?CarbonInterface $issuedAt = null): Secret
    {
        MachineTokens::refuseSession($identity instanceof MachineIdentity);

        if (!$session instanceof EloquentSession || !$session instanceof Model) {
            return $this->encode($this->accessClaims($identity, $principal, $tenant, $session, $issuedAt)[0], TokenType::ACCESS);
        }

        SessionLookup::assertOnStorage($session);

        return $session->getConnection()->transaction(function () use ($identity, $principal, $tenant, $session, $issuedAt): Secret {

            IssuanceGuard::hold($session);

            return $this->issueGuardedAccessToken($identity, $principal, $tenant, $session, TokenLifetimes::issueTime($issuedAt))->token;
        });
    }

    /**
     * Encode an access token for the session inside the transaction of the
     * issuer that already wrote the session's row, and return it with its
     * expiry.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \Carbon\CarbonInterface  $issuedAt
     * @param  bool  $inserted
     * @return \SineMacula\Laravel\Authentication\Jwt\IssuedAccessToken
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     *
     * @internal
     */
    public function issueGuardedAccessToken(
        Identity $identity,
        Principal $principal,
        ?Tenant $tenant,
        EloquentSession&Model $session,
        CarbonInterface $issuedAt,
        bool $inserted = false,
    ): IssuedAccessToken {
        MachineTokens::refuseSession($identity instanceof MachineIdentity);

        [$payload, $expiresAt] = $this->accessClaims($identity, $principal, $tenant, $session, $issuedAt, null, !$inserted);

        return new IssuedAccessToken($this->encode($payload, TokenType::ACCESS), $expiresAt, $expiresAt->getTimestamp() - TokenLifetimes::issueTime($issuedAt)->getTimestamp());
    }

    /**
     * Encode the access token a client credentials exchange hands a non-human
     * identity for the API key it was exchanged for.
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
        [$payload] = $this->accessClaims($identity, $principal, $tenant, null, $issuedAt, $notAfter);

        return $this->encode([...$payload, ...MachineTokens::claims($credentialId, $scopes)], TokenType::ACCESS);
    }

    /**
     * Encode a refresh token bound to the session, expiring when the session
     * does.
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
     * Decode and verify a token, returning its claims or `null` on any failure.
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

        /** @var array<string, mixed> $claims */
        $claims = array_filter((array) $payload, static fn (mixed $key): bool => is_string($key), ARRAY_FILTER_USE_KEY);

        return $this->matchesExpectedClaims($claims, $typ, $expectedType) ? $claims : null;
    }

    /**
     * The claims of an access token for the context, and when it expires.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\Carbon\CarbonInterface  $issuedAt
     * @param  ?\Carbon\CarbonInterface  $notAfter
     * @param  bool  $currentProofs
     * @return array{0: array<string, mixed>, 1: \Carbon\CarbonImmutable}
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Random\RandomException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException
     */
    private function accessClaims(
        Identity $identity,
        Principal $principal,
        ?Tenant $tenant,
        ?Session $session,
        ?CarbonInterface $issuedAt,
        ?CarbonInterface $notAfter = null,
        bool $currentProofs = true,
    ): array {
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
            $payload = [...$payload, ...$this->sessionClaims($session, $issuedAt, $currentProofs)];
        }

        $payload[Claims::JWT_ID->value]     = RefreshTokenHasher::generate();
        $payload[Claims::ISSUED_AT->value]  = $issuedAt->getTimestamp();
        $payload[Claims::EXPIRES_AT->value] = $expiresAt->getTimestamp();

        return [$payload, $expiresAt];
    }

    /**
     * The claims an access token for the session carries, read from the writer.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  \Carbon\CarbonImmutable  $issuedAt
     * @param  bool  $current
     * @return array<string, mixed>
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private function sessionClaims(Session $session, CarbonImmutable $issuedAt, bool $current): array
    {
        $sessionId = $this->requireClaimValue(Claims::SESSION_ID, $session->getSessionIdentifier());
        $summary   = WriteConnection::during($session, static fn (): AuthenticationSummary => AuthenticationClaims::forSession($session, $current));

        return [
            Claims::SESSION_ID->value             => $sessionId,
            Claims::AUTH_TIME->value              => min($summary->authenticatedAt->getTimestamp(), $issuedAt->getTimestamp()),
            Claims::AUTHENTICATION_METHODS->value => $summary->methods,
        ];
    }

    /**
     * Return when the session ends, refusing a session that has ended or has no
     * idle deadline.
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
     * Stringify the value of a claim the token cannot do without, throwing when
     * it would be missing.
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
     * key.
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
     * Run firebase/php-jwt with the configured leeway, returning the header's
     * `typ` and the payload, or `null` on failure.
     *
     * php-jwt exposes leeway only through the static `JWT::$leeway`, so the
     * previous value is restored after the decode.
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
     * Verify the header type, guard, issuer, audience, required claims and
     * profile shape of the token.
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
     * keeps it.
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
     * Locate the first guard, issuer or audience mismatch, or return `null`
     * when every check passes.
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
