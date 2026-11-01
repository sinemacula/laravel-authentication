<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * Plain-object `Identity` fixture: an identity that is not an Eloquent model,
 * so it needs no database and a queued event keeps only its identifier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PlainIdentityFixture implements Identity
{
    /**
     * Constructor.
     *
     * @param  int|string  $id
     * @param  string  $password
     */
    public function __construct(

        /** Stable identifier used as the `sub` claim. */
        public int|string $id,

        /** Pre-hashed password used for the `getAuthPassword()` accessor. */
        public string $password = 'hashed-password',
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
     * @param  ?string  $value
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
