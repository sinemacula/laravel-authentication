<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Scopes;

use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException;

/**
 * The form scopes take in the package: RFC 6749 scope tokens, kept as an
 * ordered list without duplicates, and written as one space-separated string in
 * a token's `scope` claim and an OAuth response. The package never reads
 * meaning into a scope.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Scopes
{
    /** @var int Longest scope accepted, in bytes. */
    public const int MAX_LENGTH = 255;

    /** @var string An RFC 6749 scope token: printable ASCII except space, `"` and `\`. */
    private const string TOKEN_PATTERN = '/^[\x21\x23-\x5B\x5D-\x7E]+$/D';

    /**
     * Bring scopes to their stored form: each a well-formed scope token of at
     * most 255 bytes, duplicates removed, the first occurrence's order kept.
     *
     * @param  array<array-key, mixed>  $scopes
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException
     */
    public static function normalise(array $scopes): array
    {
        $malformed = [];

        foreach ($scopes as $scope) {

            if (self::isToken($scope)) {
                continue;
            }

            $malformed[] = is_string($scope) ? $scope : get_debug_type($scope);
        }

        if ($malformed !== []) {
            $message = 'Each scope must be an RFC 6749 scope token (printable ASCII other than space, `"` and `\`)'
                . ' of at most ' . self::MAX_LENGTH . ' bytes.';

            throw new InvalidScopeException($message, $malformed);
        }

        /** @var list<string> */
        return array_values(array_unique($scopes));
    }

    /**
     * Read a space-separated scope string (RFC 6749 section 3.3): tokens
     * separated by single spaces, or the empty string for none.
     *
     * @param  string  $scope
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException
     */
    public static function parse(string $scope): array
    {
        return $scope === '' ? [] : self::normalise(explode(' ', $scope));
    }

    /**
     * Write scopes as one space-separated string.
     *
     * @param  list<string>  $scopes
     * @return string
     */
    public static function format(array $scopes): string
    {
        return implode(' ', $scopes);
    }

    /**
     * Whether every requested scope is one of those granted.
     *
     * @param  list<string>  $requested
     * @param  list<string>  $granted
     * @return bool
     */
    public static function isSubset(array $requested, array $granted): bool
    {
        return array_diff($requested, $granted) === [];
    }

    /**
     * The scopes a credential of the principal on the guard may grant: the
     * given scopes normalised, then held to the scope registry.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\ScopeRegistry  $registry
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  array<array-key, mixed>  $scopes
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException
     */
    public static function grantable(ScopeRegistry $registry, string $guard, Principal $principal, array $scopes): array
    {
        $normalised = self::normalise($scopes);
        $rejected   = array_values(array_intersect($registry->rejected($guard, $principal, $normalised), $normalised));

        if ($rejected !== []) {
            throw new InvalidScopeException("The scope registry does not allow these scopes for the principal on guard [{$guard}].", $rejected);
        }

        return $normalised;
    }

    /**
     * Whether the value is a well-formed scope token.
     *
     * @param  mixed  $scope
     * @return bool
     */
    private static function isToken(mixed $scope): bool
    {
        return is_string($scope) && strlen($scope) <= self::MAX_LENGTH && preg_match(self::TOKEN_PATTERN, $scope) === 1;
    }
}
