<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Scopes\Scopes;

/**
 * The `cid` and `scope` claims of a non-human identity's client credentials
 * token, which never names a session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class MachineTokens
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Refuse to issue a session's token to a non-human identity.
     *
     * @param  bool  $machine
     * @return void
     *
     * @throws \LogicException
     */
    public static function refuseSession(bool $machine): void
    {
        if ($machine) {
            throw new \LogicException('A non-human identity has no session: it gets access tokens only from a client credentials exchange.');
        }
    }

    /**
     * The claims naming the API key a client credentials token was exchanged
     * for and the scopes it grants.
     *
     * @param  string  $credentialId
     * @param  list<string>  $scopes
     * @return array{cid: string, scope: string}
     *
     * @throws \InvalidArgumentException
     */
    public static function claims(#[\SensitiveParameter] string $credentialId, array $scopes): array
    {
        if (!Str::isUuid($credentialId)) {
            throw new \InvalidArgumentException('Cannot issue a client credentials token without its `cid` claim: the API key id must be a UUID.');
        }

        return [Claims::CREDENTIAL_ID->value => $credentialId, Claims::SCOPE->value => Scopes::format(Scopes::normalize($scopes))];
    }

    /**
     * The API key id and scopes a token's claims name, `null` for a token that
     * names no key, or `false` for malformed claims.
     *
     * @param  array<string, mixed>  $claims
     * @return array{0: string, 1: list<string>}|false|null
     */
    public static function credential(array $claims): array|false|null
    {
        $credentialId = $claims[Claims::CREDENTIAL_ID->value] ?? null;

        if ($credentialId === null) {
            return null;
        }

        $scope  = $claims[Claims::SCOPE->value] ?? null;
        $scopes = is_string($scope) ? self::scopes($scope) : null;

        return is_string($credentialId) && Str::isUuid($credentialId) && $scopes !== null && ($claims[Claims::SESSION_ID->value] ?? null) === null
            ? [$credentialId, $scopes]
            : false;
    }

    /**
     * The scopes a `scope` claim names, or `null` when it is not a scope
     * string.
     *
     * @param  string  $scope
     * @return ?list<string>
     */
    private static function scopes(string $scope): ?array
    {
        try {
            return Scopes::parse($scope);
        } catch (InvalidScopeException) {
            return null;
        }
    }
}
