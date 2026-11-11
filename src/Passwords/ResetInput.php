<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalizers;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;

/**
 * Reads what a password reset request or submission carries, as strings.
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

    /** @var string Input key of a reset code's challenge id. */
    public const string CHALLENGE_KEY = 'challenge';

    /** @var string Input key of the new password. */
    public const string PASSWORD_KEY = 'password';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Refuse a type that is not a valid identifier type or has no registered
     * normaliser.
     *
     * @param  \SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalizers  $normalizers
     * @param  string  $type
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public static function assertCodeType(IdentifierNormalizers $normalizers, string $type): void
    {
        if (!$normalizers->has(IdentifierType::assertValid($type))) {
            $message = sprintf('Password reset codes need a normaliser registered for identifier type [%s] in `authentication.identifiers.normalizers`.', $type);

            throw new \InvalidArgumentException($message);
        }
    }

    /**
     * The identifier the input names under the type, as a string, or `null`.
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
