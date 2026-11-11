<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ApiKeys;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * Decides whom a presented key authenticates on a guard, and why not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ApiKeyAuthentication
{
    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     * @param  \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy  $policy
     */
    public function __construct(

        /** Name of the guard the key must authenticate for. */
        private string $guard,

        /** The credential kind the guard's application must allow: `api_key` or `client_credentials`. */
        private string $method,

        /** The guard's identity provider. */
        private IdentityProvider $provider,

        /** The guard's principal resolver. */
        private PrincipalResolver $resolver,

        /** The application policy. */
        private ApplicationPolicy $policy,
    ) {}

    /**
     * Authenticate the key's public part and secret at the time.
     *
     * @param  string  $public
     * @param  string  $secret
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\ApiKeys\ApiKeyOutcome
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    public function authenticate(string $public, #[\SensitiveParameter] string $secret, CarbonImmutable $now): ApiKeyOutcome
    {
        $key      = ApiKeyToken::isWellFormed($public, $secret) ? ApiKeyLookup::find($public) : null;
        $verified = ApiKeyLookup::verifies($key, $secret);

        if ($key === null || !$verified) {
            return new ApiKeyOutcome($key, new Refused(FailureReason::CREDENTIAL_INVALID));
        }

        $refusal = ApiKeyLookup::refusal($key, $this->guard, $now) ?? ($this->policy->allowsMethod($this->guard, $this->method) ? null : FailureReason::METHOD_NOT_ALLOWED);

        return new ApiKeyOutcome($key, $refusal === null
            ? (new ApiKeyAdmission($this->guard, $this->provider, $this->resolver))->admit($key)
            : new Refused($refusal));
    }
}
