<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;

/**
 * Audience policy double that decides verification per principal, as the
 * contract allows: an identifier a sign-in used may act within any tenant but
 * the one that invited it, whose principals are refused as
 * `identifier_unverified` to every sign-in that used an identifier. A sign-in
 * that used none, and a refresh, are not refused. Everything else is the
 * wrapped policy's.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class InvitedTenantAudiencePolicy implements AudiencePolicy
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\AudiencePolicy  $inner
     * @param  mixed  $invitingTenant
     */
    public function __construct(

        /** The policy that decides everything else. */
        private AudiencePolicy $inner,

        /** Identifier of the tenant whose principals an identifier is refused. */
        private mixed $invitingTenant,
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
     * Refuse a principal of the inviting tenant to a sign-in that used an
     * identifier, otherwise answer as the wrapped policy.
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
        if ($identifierType !== null && IdentifierCoercion::matches($principal->getTenant()?->getTenantIdentifier(), $this->invitingTenant)) {
            return FailureReason::IDENTIFIER_UNVERIFIED;
        }

        return $this->inner->admit($guard, $identity, $principal, $identifierType);
    }

    /**
     * The wrapped policy's lifetimes.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes
     */
    #[\Override]
    public function lifetimes(string $guard, Principal $principal): TokenLifetimes
    {
        return $this->inner->lifetimes($guard, $principal);
    }
}
