<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ApiKeys;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Sessions\Admission\RefusedSignIn;

/**
 * Decides whom a presented key authenticates on a guard, and why not, in order:
 * the key must be one in form, and its public part must name a key whose secret
 * it is (`credential_invalid`, the same for a malformed key, an unknown public
 * part and a wrong secret); the key must be the guard's
 * (`credential_guard_mismatch`), not revoked (`credential_revoked`) and not
 * expired (`credential_expired`); the guard's audience must allow the
 * credential (`method_not_allowed`); then its owner and principal are admitted
 * (`ApiKeyAdmission`). No password hashing is done: the secret's SHA-256 digest
 * is compared in constant time, against a fixed digest when no key matched.
 *
 * Built for one use with the guard's current collaborators, so it keeps nothing
 * between requests.
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
     * @param  \SineMacula\Laravel\Authentication\Contracts\AudiencePolicy  $audience
     */
    public function __construct(

        /** Name of the guard the key must authenticate for. */
        private string $guard,

        /** The credential kind the guard's audience must allow: `api_key` or `client_credentials`. */
        private string $method,

        /** The guard's identity provider. */
        private IdentityProvider $provider,

        /** The guard's principal resolver. */
        private PrincipalResolver $resolver,

        /** The audience policy. */
        private AudiencePolicy $audience,
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
            return new ApiKeyOutcome($key, new RefusedSignIn(FailureReason::CREDENTIAL_INVALID));
        }

        $refusal = ApiKeyLookup::refusal($key, $this->guard, $now) ?? ($this->audience->allowsMethod($this->guard, $this->method) ? null : FailureReason::METHOD_NOT_ALLOWED);

        return new ApiKeyOutcome($key, $refusal === null
            ? (new ApiKeyAdmission($this->guard, $this->provider, $this->resolver, $this->audience))->admit($key)
            : new RefusedSignIn($refusal));
    }
}
