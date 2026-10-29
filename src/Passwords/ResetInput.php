<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalisers;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;

/**
 * Reads what a password reset request or submission carries, as strings:
 * anything else under a key reads as missing, so no list, number of the wrong
 * kind or object reaches a lookup or a hash.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ResetInput
{
    /** @var string Input key of a reset link's token. */
    public const string TOKEN_KEY = 'token';

    /** @var string Input key of a reset code. */
    public const string CODE_KEY = 'code';

    /** @var string Input key of the new password. */
    public const string PASSWORD_KEY = 'password';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Refuse a type a reset code cannot be bound to: one that is not a valid
     * identifier type, or has no registered normaliser to bring it to the one
     * form a code is bound to.
     *
     * @param  \SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalisers  $normalisers
     * @param  string  $type
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertCodeType(IdentifierNormalisers $normalisers, string $type): void
    {
        if (!$normalisers->has(IdentifierType::assertValid($type))) {
            $message = sprintf('Password reset codes need a normaliser registered for identifier type [%s] in `authentication.identifiers.normalisers`.', $type);

            throw new \InvalidArgumentException($message);
        }
    }

    /**
     * The identifier the input names under the type, when it is a string, a
     * `Stringable` or an integer (a numeric identifier sent as a JSON number),
     * as a string.
     *
     * @param  array<array-key, mixed>  $input
     * @param  string  $type
     * @return ?string
     */
    public static function identifier(#[\SensitiveParameter] array $input, string $type): ?string
    {
        $identifier = $input[$type] ?? null;

        return is_string($identifier) || is_int($identifier) || $identifier instanceof \Stringable ? (string) $identifier : null;
    }

    /**
     * The string the input holds under the key, or `null`.
     *
     * @param  array<array-key, mixed>  $input
     * @param  string  $key
     * @return ?string
     */
    public static function secret(#[\SensitiveParameter] array $input, string $key): ?string
    {
        $value = $input[$key] ?? null;

        return is_string($value) ? $value : null;
    }
}
