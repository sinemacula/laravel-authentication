<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs;

/**
 * The authentication method reference values a proof carries (RFC 8176's `amr`
 * values, or private ones), as a method or an adapter reports them.
 *
 * A list of at most `MAX_VALUES` values, each of 1 to `MAX_LENGTH` printable
 * ASCII characters other than a quote or a backslash (the registered values and
 * URNs are), so the stored list fits its column. `mfa` is reserved: it is never
 * a proof's own value, and the token's `amr` gains it only from an accepted
 * evaluation that reports multifactor authentication.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AuthenticationMethods
{
    /** @var string The reserved value for multifactor authentication (RFC 8176). */
    public const string MULTIFACTOR = 'mfa';

    /** @var int Most values a proof carries. */
    public const int MAX_VALUES = 8;

    /** @var int Longest value, in characters. */
    public const int MAX_LENGTH = 48;

    /** @var string What a value may be made of: printable ASCII but a quote or a backslash, which JSON would escape. */
    private const string VALUE_PATTERN = '/^[\x21\x23-\x5B\x5D-\x7E]{1,48}$/';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The values, once they are known to be a list within the limits that does
     * not name `mfa`.
     *
     * @param  array<array-key, mixed>  $methods
     * @return list<string>
     *
     * @throws \InvalidArgumentException
     */
    public static function assertValid(array $methods): array
    {
        if (!array_is_list($methods) || count($methods) > self::MAX_VALUES) {
            throw new \InvalidArgumentException(sprintf('A proof\'s `amr` values must be a list of at most %d.', self::MAX_VALUES));
        }

        foreach ($methods as $method) {

            if (!is_string($method) || preg_match(self::VALUE_PATTERN, $method) !== 1) {
                throw new \InvalidArgumentException(sprintf('A proof\'s `amr` value must be 1 to %d printable ASCII characters, no quote or backslash.', self::MAX_LENGTH));
            }

            if ($method === self::MULTIFACTOR) {
                throw new \InvalidArgumentException('`mfa` is reserved: it is never a proof\'s own `amr` value, only an accepted evaluation\'s report.');
            }
        }

        return $methods;
    }
}
