<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * Plain-object identity, not an Eloquent model, that keeps its identifiers and
 * their verification in memory.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubVerifiableIdentity implements HasVerifiableIdentifiers, Identity
{
    /** @var array<string, true> Identifier types verified so far. */
    private array $verified = [];

    /**
     * Constructor.
     *
     * @param  int  $id
     * @param  array<string, string>  $identifiers
     */
    public function __construct(

        /** Stable identifier. */
        public readonly int $id,

        /** Identifiers by type. */
        private readonly array $identifiers,
    ) {}

    /**
     * The identifier of the type, if any.
     *
     * @param  string  $type
     * @return ?string
     */
    #[\Override]
    public function getIdentifierForVerification(string $type): ?string
    {
        return $this->identifiers[$type] ?? null;
    }

    /**
     * Whether the identifier of the type was verified.
     *
     * @param  string  $type
     * @return bool
     */
    #[\Override]
    public function hasVerifiedIdentifier(string $type): bool
    {
        return isset($this->verified[$type]);
    }

    /**
     * Record the identifier as verified when it is the current one and not
     * verified yet.
     *
     * @param  string  $type
     * @param  string  $identifier
     * @return bool
     *
     * @imperative
     */
    #[\Override]
    public function markIdentifierAsVerified(string $type, string $identifier): bool
    {
        if (($this->identifiers[$type] ?? null) !== $identifier || isset($this->verified[$type])) {
            return false;
        }

        $this->verified[$type] = true;

        return true;
    }

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
     * @return int
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
        return '';
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
