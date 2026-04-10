<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * Plain-object `Identity` fixture used by the event serialisation
 * round-trip tests. Intentionally NOT an Eloquent model so the
 * `SerializesModels` trait leaves the instance untouched during
 * serialize - the test asserts the round trip on a uniformly
 * supported payload without needing a database connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class PlainIdentityFixture implements Identity
{
    /**
     * Constructor.
     *
     * @param  int|string  $id
     * @param  string  $password
     */
    public function __construct(
        /** Stable identifier used as the `sub` claim. */
        public readonly int|string $id,

        /** Pre-hashed password used for the `getAuthPassword()` accessor. */
        public readonly string $password = 'hashed-password',
    ) {}

    /**
     * Get the name of the unique identifier for the user.
     *
     * @return string
     */
    #[\Override]
    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    /**
     * Get the unique identifier for the user.
     *
     * @return int|string
     */
    #[\Override]
    public function getAuthIdentifier(): mixed
    {
        return $this->id;
    }

    /**
     * Get the name of the password attribute for the user.
     *
     * @return string
     */
    #[\Override]
    public function getAuthPasswordName(): string
    {
        return 'password';
    }

    /**
     * Get the password for the user.
     *
     * @return string
     */
    #[\Override]
    public function getAuthPassword(): string
    {
        return $this->password;
    }

    /**
     * Get the token value for the "remember me" session.
     *
     * @return string
     */
    #[\Override]
    public function getRememberToken(): string
    {
        return '';
    }

    /**
     * Set the token value for the "remember me" session.
     *
     * @param  string  $value
     * @return void
     */
    #[\Override]
    public function setRememberToken(#[\SensitiveParameter] $value): void // phpcs:ignore Squiz.Commenting.FunctionComment.ScalarTypeHintMissing
    {
        unset($value);
    }

    /**
     * Get the column name for the "remember me" token.
     *
     * @return string
     */
    #[\Override]
    public function getRememberTokenName(): string
    {
        return 'remember_token';
    }
}
