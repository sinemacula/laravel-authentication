<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use Carbon\CarbonInterface;
use SineMacula\Laravel\Authentication\Contracts\HasTokensValidAfter;
use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * A non-Eloquent identity that records a "tokens valid after" cutoff it reads
 * as none.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PlainCutoffIdentity implements HasTokensValidAfter, Identity
{
    /**
     * Constructor.
     *
     * @param  int|string  $id
     * @param  bool  $moves
     */
    public function __construct(

        /** The auth identifier. */
        public int|string $id,

        /** Whether it says it moved the cutoff when asked to. */
        public bool $moves = false,
    ) {}

    /**
     * Return the auth identifier's name.
     *
     * @return string
     */
    #[\Override]
    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    /**
     * Return the auth identifier.
     *
     * @return int|string
     */
    #[\Override]
    public function getAuthIdentifier(): mixed
    {
        return $this->id;
    }

    /**
     * Return the password column's name.
     *
     * @return string
     */
    #[\Override]
    public function getAuthPasswordName(): string
    {
        return 'password';
    }

    /**
     * Return the password hash.
     *
     * @return string
     */
    #[\Override]
    public function getAuthPassword(): string
    {
        return 'hashed-password';
    }

    /**
     * Return the remember token, which it has none of.
     *
     * @return string
     */
    #[\Override]
    public function getRememberToken(): string
    {
        return '';
    }

    /**
     * Ignore the remember token.
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
     * Return the remember token's name.
     *
     * @return string
     */
    #[\Override]
    public function getRememberTokenName(): string
    {
        return 'remember_token';
    }

    /**
     * Return the cutoff, which it has none of.
     *
     * @return ?\Carbon\CarbonInterface
     */
    #[\Override]
    public function getTokensValidAfter(): ?CarbonInterface
    {
        return null;
    }

    /**
     * Say whether it moved the cutoff, moving nothing.
     *
     * @param  \Carbon\CarbonInterface  $time
     * @return bool
     *
     * @imperative
     */
    #[\Override]
    public function invalidateTokensIssuedBefore(CarbonInterface $time): bool
    {
        unset($time);

        return $this->moves;
    }
}
