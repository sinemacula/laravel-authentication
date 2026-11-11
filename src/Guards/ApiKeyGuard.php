<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use SineMacula\Laravel\Authentication\Admission\Admitted;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyAuthentication;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyLookup;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyOutcome;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyToken;
use SineMacula\Laravel\Authentication\Context\Enums\CredentialKind;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\BearerForms;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;

/**
 * API key guard, the `api_key` driver: authenticates a request by the API key
 * in its `Authorization: Bearer <key>` header, for non-human identities.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ApiKeyGuard extends AbstractGuard
{
    /** @var string The credential kind an application lists to accept API keys, and the method its contexts report. */
    public const string METHOD = 'api_key';

    /**
     * Refuse the sign-in: a non-human identity has no interactive sign-in.
     *
     * @param  array<string, mixed>  $credentials
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @return bool
     *
     * @imperative
     */
    #[\Override]
    public function attempt(#[\SensitiveParameter] array $credentials, ?Principal $principal = null, ?Session $session = null): bool
    {
        $context = new EventContext($this->context->name(), $this->context->client(), method: PasswordSignIn::NAME);

        $this->context->dispatch(new AuthenticationFailed($context, AuthenticationFlow::SIGN_IN, FailureReason::METHOD_NOT_ALLOWED));

        return false;
    }

    /**
     * Whether the API key under `api_key` would authenticate a request now,
     * without binding anything, recording its use or dispatching any event.
     *
     * @param  array<array-key, mixed>  $credentials
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    #[\Override]
    public function validate(#[\SensitiveParameter] array $credentials = []): bool
    {
        $key = $credentials[self::METHOD] ?? null;

        return is_string($key) && !$this->authenticate($key, CarbonImmutable::now()->startOfSecond())->admission instanceof Refused;
    }

    /**
     * Resolve the identity from the request's API key.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    #[\Override]
    protected function resolveUserFromRequest(): ?Identity
    {
        $request   = $this->context->request();
        $presented = $request->bearerToken();

        if ($presented === null || $presented === '' || BearerForms::defersTo(BearerForms::API_KEY, $request, $presented)) {
            return null;
        }

        $now       = CarbonImmutable::now()->startOfSecond();
        $outcome   = $this->authenticate($presented, $now);
        $admission = $outcome->admission;
        $key       = $outcome->key;

        if ($admission instanceof Admitted && $key !== null) {

            $this->bindVerifiedContext($admission->identity, $admission->principal, null, $admission->tenant, self::METHOD, false, $key->id, $key->scopes, CredentialKind::API_KEY);

            ApiKeyLookup::recordUse($key, $now);

            return $admission->identity;
        }

        if ($admission instanceof Refused) {
            $this->context->dispatch($outcome->failure($admission, $this->context->name(), AuthenticationFlow::API_KEY, self::METHOD, $this->context->client()));
        }

        return null;
    }

    /**
     * Authenticate a presented key on this guard at the time.
     *
     * @param  string  $presented
     * @param  \Carbon\CarbonImmutable  $now
     * @return \SineMacula\Laravel\Authentication\ApiKeys\ApiKeyOutcome
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Resolvers\UnresolvableIdentityException
     */
    private function authenticate(#[\SensitiveParameter] string $presented, CarbonImmutable $now): ApiKeyOutcome
    {
        [$public, $secret] = ApiKeyToken::split($presented) ?? ['', ''];

        /** @var \SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy $policy */
        $policy = Container::getInstance()->make(ApplicationPolicy::class);

        $context = $this->context;

        return (new ApiKeyAuthentication($context->name(), self::METHOD, $context->provider(), $context->resolver(), $policy))->authenticate($public, $secret, $now);
    }
}
