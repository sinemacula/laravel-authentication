<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\SubjectType;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * The shape rules of the package's token profile that go beyond a claim being
 * present: the header type a token's `typ` names, what an access token's claims
 * must say about its subject, its session and its tenant, and which tenant one
 * may name when it is issued.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class TokenProfile
{
    /** @var string The media type prefix a header type may carry (RFC 7515 §4.1.9). */
    private const string MEDIA_TYPE_PREFIX = 'application/';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The token type a JOSE header's `typ` names, or `null` for a missing,
     * unknown or malformed one. Compared without regard to case and with an
     * optional `application/` prefix removed, as RFC 7515 §4.1.9 and RFC 9068
     * §4 allow (`at+jwt` or `application/at+jwt`).
     *
     * @param  mixed  $typ
     * @return ?\SineMacula\Laravel\Authentication\Jwt\Enums\TokenType
     */
    public static function headerType(mixed $typ): ?TokenType
    {
        if (!is_string($typ)) {
            return null;
        }

        $typ = strtolower($typ);

        return TokenType::tryFrom(str_starts_with($typ, self::MEDIA_TYPE_PREFIX) ? substr($typ, strlen(self::MEDIA_TYPE_PREFIX)) : $typ);
    }

    /**
     * The `tenant_id` an access token for the principal may carry: the tenant
     * identifier given, once it is known to be the one of the tenant the
     * principal acts within (its `getTenant()`, read on the write connection).
     * A principal acts only within its own tenant, so a token never names
     * another.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $tenantId
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public static function ownTenant(Principal $principal, string $tenantId): string
    {
        $own = WriteConnection::during($principal, static fn (): ?Tenant => $principal->getTenant());

        if (!IdentifierCoercion::matches($own?->getTenantIdentifier(), $tenantId)) {
            throw new \InvalidArgumentException('Cannot issue a token naming a tenant the principal does not act within: pass the tenant its admission loaded.');
        }

        return $tenantId;
    }

    /**
     * Why an access token's claims break the profile, or `null` when they keep
     * it: the API key a client credentials token names must be well formed, and
     * its subject type `machine` exactly when it names one (`person`
     * otherwise); a token that names a session carries an integer `auth_time`
     * not after its issue time plus the leeway and an `amr` that is a list of
     * non-empty strings, possibly empty, and one that names none carries
     * neither; a `tenant_id` is a non-empty string.
     *
     * @param  array<string, mixed>  $claims
     * @param  int  $leewaySeconds
     * @return ?string
     */
    public static function accessFailure(array $claims, int $leewaySeconds): ?string
    {
        $credential = MachineTokens::credential($claims);
        $subject    = $credential === null ? SubjectType::PERSON : SubjectType::MACHINE;

        return match (true) {
            $credential === false                                              => 'JWT credential claims malformed',
            ($claims[Claims::SUBJECT_TYPE->value] ?? null) !== $subject->value => 'JWT subject type mismatch',
            !self::isAuthenticationShaped($claims, $leewaySeconds)             => 'JWT authentication claims malformed',
            !self::isTenantShaped($claims)                                     => 'JWT tenant claim malformed',
            default                                                            => null,
        };
    }

    /**
     * Why a refresh token's claims break the profile, or `null` when they keep
     * it: a refresh token names a session, so it can never name an API key, and
     * one that does is malformed.
     *
     * @param  array<string, mixed>  $claims
     * @return ?string
     */
    public static function refreshFailure(array $claims): ?string
    {
        return MachineTokens::credential($claims) === false ? 'JWT credential claims malformed' : null;
    }

    /**
     * Whether the claims carry `auth_time` and `amr` exactly when they name a
     * session, each well formed.
     *
     * @param  array<string, mixed>  $claims
     * @param  int  $leewaySeconds
     * @return bool
     */
    private static function isAuthenticationShaped(array $claims, int $leewaySeconds): bool
    {
        if (($claims[Claims::SESSION_ID->value] ?? null) === null) {
            return !array_key_exists(Claims::AUTH_TIME->value, $claims) && !array_key_exists(Claims::AUTHENTICATION_METHODS->value, $claims);
        }

        $authTime = $claims[Claims::AUTH_TIME->value] ?? null;
        $issuedAt = $claims[Claims::ISSUED_AT->value] ?? null;
        $inTime   = is_int($authTime) && is_int($issuedAt) && $authTime <= $issuedAt + $leewaySeconds;

        return $inTime && self::isMethodList($claims[Claims::AUTHENTICATION_METHODS->value] ?? null);
    }

    /**
     * Whether the value is a list of non-empty strings, possibly empty.
     *
     * @param  mixed  $methods
     * @return bool
     */
    private static function isMethodList(mixed $methods): bool
    {
        if (!is_array($methods) || !array_is_list($methods)) {
            return false;
        }

        foreach ($methods as $method) {
            if (!is_string($method) || $method === '') {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether the claims name no tenant, or name one by a non-empty string.
     *
     * @param  array<string, mixed>  $claims
     * @return bool
     */
    private static function isTenantShaped(array $claims): bool
    {
        if (!array_key_exists(Claims::TENANT_ID->value, $claims)) {
            return true;
        }

        $tenant = $claims[Claims::TENANT_ID->value];

        return is_string($tenant) && $tenant !== '';
    }
}
