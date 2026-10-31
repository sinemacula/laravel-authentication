<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;

/**
 * Audience policy an application rebinds to decide which principals may use a
 * guard: the principals the rule names are refused as `principal_ineligible`,
 * whatever identifier the sign-in used, and everything else is the wrapped
 * policy's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RefusingAudiencePolicy implements AudiencePolicy
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AudiencePolicy  $inner
     * @param  \Closure(string, \SineMacula\Laravel\Authentication\Contracts\Principal): bool  $refuses
     */
    public function __construct(

        /** The policy that decides everything else. */
        private AudiencePolicy $inner,

        /** Whether the guard refuses the principal. */
        private \Closure $refuses,
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
     * Refuse a principal the rule names as `principal_ineligible`, otherwise
     * answer as the wrapped policy.
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
        return ($this->refuses)($guard, $principal) ? FailureReason::PRINCIPAL_INELIGIBLE : $this->inner->admit($guard, $identity, $principal, $identifierType);
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
