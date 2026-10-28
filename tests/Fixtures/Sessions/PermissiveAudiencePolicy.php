<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;

/**
 * Audience policy double that allows every method and admits every principal,
 * with the same lifetimes for every guard and principal, for guard tests whose
 * guards no configuration describes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PermissiveAudiencePolicy implements AudiencePolicy
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $lifetimes
     */
    public function __construct(

        /** Lifetimes for every guard and principal. */
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
     * Admit every principal.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?string  $identifierType
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    #[\Override]
    public function admit(string $guard, Identity $identity, Principal $principal, ?string $identifierType): ?FailureReason
    {
        unset($guard, $identity, $principal, $identifierType);

        return null;
    }

    /**
     * The given lifetimes, whatever the guard and principal.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes
     */
    #[\Override]
    public function lifetimes(string $guard, Principal $principal): TokenLifetimes
    {
        unset($guard, $principal);

        return $this->lifetimes;
    }
}
