<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Jwt;

use Illuminate\Support\Str;
use SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Scopes\Scopes;

/**
 * How a non-human identity's tokens differ from a session's: it gets no session
 * token at all, and the access token a client credentials exchange issues it
 * names the API key it was exchanged for in `cid` and carries that key's
 * granted scopes in `scope`. A token with `cid` must carry `scope` (the empty
 * string for none) and name no device.
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
     * Refuse to issue a session's token to a non-human identity, which has no
     * device, no refresh and no interactive sign-in.
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

        return [Claims::CREDENTIAL_ID->value => $credentialId, Claims::SCOPE->value => Scopes::format(Scopes::normalise($scopes))];
    }

    /**
     * The API key id and scopes a token's claims name, `null` for a token that
     * names no key, or `false` for claims that name one malformed: a `cid` that
     * is not a UUID, a `scope` that is not a scope string, or a device.
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

        return is_string($credentialId) && Str::isUuid($credentialId) && $scopes !== null && ($claims[Claims::DEVICE_ID->value] ?? null) === null
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
