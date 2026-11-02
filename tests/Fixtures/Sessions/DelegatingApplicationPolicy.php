<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;

/**
 * Application policy of an application's own that wraps another and answers
 * everything as it does, as a policy that adds a rule of its own to the
 * package's starts out.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DelegatingApplicationPolicy implements ApplicationPolicy
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy  $inner
     */
    public function __construct(

        /** The policy that decides everything. */
        private ApplicationPolicy $inner,
    ) {}

    /**
     * The wrapped policy's answer.
     *
     * @param  string  $guard
     * @param  string  $method
     * @return bool
     */
    #[\Override]
    public function allowsMethod(string $guard, string $method): bool
    {
        return $this->inner->allowsMethod($guard, $method);
    }

    /**
     * The wrapped policy's answer.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $identifierType
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    #[\Override]
    public function admitIdentifier(string $guard, Identity $identity, ?string $identifierType): ?FailureReason
    {
        return $this->inner->admitIdentifier($guard, $identity, $identifierType);
    }

    /**
     * The wrapped policy's lifetimes.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes
     */
    #[\Override]
    public function lifetimes(string $guard): TokenLifetimes
    {
        return $this->inner->lifetimes($guard);
    }
}
