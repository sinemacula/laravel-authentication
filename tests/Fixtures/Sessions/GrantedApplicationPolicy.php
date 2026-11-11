<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Sessions;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Application policy that admits an identifier sign-in only once that
 * identifier's type is recorded verified.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class GrantedApplicationPolicy implements ApplicationPolicy
{
    /** @var string Table of the identifier types each identity has verified. */
    public const string VERIFICATIONS = 'application_verifications';

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy  $inner
     */
    public function __construct(

        /** The policy that decides everything else. */
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
     * @return bool
     */
    #[\Override]
    public function allowsClientSecretPost(string $guard): bool
    {
        return $this->inner->allowsClientSecretPost($guard);
    }

    /**
     * Refuse an identifier whose type the identity has no verification row for
     * as `identifier_unverified`, otherwise answer as the wrapped policy.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?string  $identifierType
     * @return ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     */
    #[\Override]
    public function admitIdentifier(string $guard, Identity $identity, ?string $identifierType): ?FailureReason
    {
        $verified = $identifierType === null || DB::table(self::VERIFICATIONS)
            ->where('identity_id', IdentifierCoercion::stringify($identity->getAuthIdentifier()))
            ->where('type', $identifierType)
            ->exists();

        return $verified ? $this->inner->admitIdentifier($guard, $identity, $identifierType) : FailureReason::IDENTIFIER_UNVERIFIED;
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
