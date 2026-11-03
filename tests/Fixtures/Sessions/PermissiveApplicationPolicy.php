<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;

/**
 * Application policy double that allows every method and admits every identity,
 * with the same lifetimes for every guard, for guard tests whose guards no
 * configuration describes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PermissiveApplicationPolicy implements ApplicationPolicy
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     */
    public function __construct(

        /** Lifetimes for every guard. */
        private TokenLifetimes $lifetimes,
    ) {}

    /**
     * Allow every method.
     *
     * @param  string  $guard
     * @param  string  $method
     * @return bool
     */
    #[\Override]
    public function allowsMethod(string $guard, string $method): bool
    {
        unset($guard, $method);

        return true;
    }

    /**
     * Allow body credentials on every guard.
     *
     * @param  string  $guard
     * @return bool
     */
    #[\Override]
    public function allowsClientSecretPost(string $guard): bool
    {
        unset($guard);

        return true;
    }

    /**
     * Admit every identity, whatever identifier it signed in with.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $identifierType
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    #[\Override]
    public function admitIdentifier(string $guard, Identity $identity, ?string $identifierType): ?FailureReason
    {
        unset($guard, $identity, $identifierType);

        return null;
    }

    /**
     * The given lifetimes, whatever the guard.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes
     */
    #[\Override]
    public function lifetimes(string $guard): TokenLifetimes
    {
        unset($guard);

        return $this->lifetimes;
    }
}
