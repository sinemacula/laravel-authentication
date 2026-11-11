<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Scopes;

use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\ScopeRegistry;
use SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException;

/**
 * The form scopes take in the package: RFC 6749 scope tokens in an ordered list
 * without duplicates.
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

    /** @var int Longest list of scopes accepted, in bytes, written space-separated. */
    public const int MAX_LIST_LENGTH = 8192;

    /** @var string An RFC 6749 scope token: printable ASCII except space, `"` and `\`. */
    private const string TOKEN_PATTERN = '/^[\x21\x23-\x5B\x5D-\x7E]+$/D';

    /**
     * Bring scopes to their stored form: well-formed tokens, duplicates
     * removed, within the length bounds.
     *
     * @param  array<array-key, mixed>  $scopes
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException
     */
    public static function normalize(array $scopes): array
    {
        $tokens    = [];
        $malformed = [];

        foreach ($scopes as $scope) {

            if (is_string($scope) && self::isToken($scope)) {
                $tokens[] = $scope;
                continue;
            }

            $malformed[] = is_string($scope) ? $scope : get_debug_type($scope);
        }

        if ($malformed !== []) {
            $message = 'Each scope must be an RFC 6749 scope token (printable ASCII other than space, `"` and `\`)'
                . ' of at most ' . self::MAX_LENGTH . ' bytes.';

            throw new InvalidScopeException($message, $malformed);
        }

        return self::withinListLength(array_values(array_unique($tokens)));
    }

    /**
     * Read a space-separated scope string (RFC 6749 section 3.3).
     *
     * @param  string  $scope
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException
     */
    public static function parse(string $scope): array
    {
        return $scope === '' ? [] : self::normalize(explode(' ', $scope));
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
     * The scopes a credential of the principal on the guard may grant,
     * normalised and held to the scope registry.
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
        $normalized = self::normalize($scopes);
        $answer     = $registry->rejected($guard, $principal, $normalized);

        if ($answer !== []) {
            $named = array_values(array_intersect($normalized, $answer));

            throw new InvalidScopeException("The scope registry does not allow these scopes for the principal on guard [{$guard}].", $named === [] ? $normalized : $named);
        }

        return $normalized;
    }

    /**
     * The scopes when, space-separated, they fit the list bound.
     *
     * @param  list<string>  $scopes
     * @return list<string>
     *
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException
     */
    private static function withinListLength(array $scopes): array
    {
        $length = -1;

        foreach ($scopes as $index => $scope) {

            $length += strlen($scope) + 1;

            if ($length > self::MAX_LIST_LENGTH) {
                throw new InvalidScopeException('The scopes, written space-separated, must be at most ' . self::MAX_LIST_LENGTH . ' bytes.', array_slice($scopes, $index));
            }
        }

        return $scopes;
    }

    /**
     * Whether the value is a well-formed scope token.
     *
     * @param  string  $scope
     * @return bool
     */
    private static function isToken(string $scope): bool
    {
        return strlen($scope) <= self::MAX_LENGTH && preg_match(self::TOKEN_PATTERN, $scope) === 1;
    }
}
