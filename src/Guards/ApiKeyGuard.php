<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use SineMacula\Laravel\Authentication\Admission\Refused;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyAuthentication;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyLookup;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyOutcome;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyToken;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;

/**
 * API key guard, the `api_key` driver: authenticates a request by the API key
 * in its `Authorization: Bearer <key>` header, for non-human identities.
 *
 * Resolution, once per request: one indexed lookup of the key's public part on
 * the write connection, the secret's SHA-256 digest compared in constant time,
 * the key held to this guard and to its revocation and expiry, the guard's
 * audience required to allow `api_key`, then the key's owner and principal
 * admitted (see `ApiKeyAuthentication`). The request binds the owner and the
 * principal with the key's scopes, as an authentication rather than a sign-in
 * (no `Validated` or `Login`), and records the key's last use, at most once per
 * `last_used_throttle_seconds`. A rejected key dispatches one
 * `AuthenticationFailed` (flow `api_key`) and nothing else. Keys carry no
 * device and no refresh.
 *
 * Nothing is counted against a limit: a key's secret cannot be guessed, and a
 * write per rejected request, or a read per request, would cost the hot path
 * more than it protects. Throttle the routes for that.
 *
 * Non-human identities have no interactive sign-in, so `attempt()` always
 * fails. `validate(['api_key' => $key])` checks a key without binding it or
 * dispatching anything.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ApiKeyGuard extends AbstractGuard
{
    /** @var string The credential kind a guard's audience lists to accept API keys, and the method its contexts report. */
    public const string METHOD = 'api_key';

    /**
     * Refuse the sign-in: a non-human identity has no password and no
     * interactive sign-in. Dispatches `AuthenticationFailed` (flow `sign_in`,
     * `method_not_allowed`) and checks nothing.
     *
     * @param  array<string, mixed>  $credentials
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return bool
     *
     * @imperative
     */
    #[\Override]
    public function attempt(#[\SensitiveParameter] array $credentials, ?Principal $principal = null, ?Device $device = null): bool
    {
        $context = new EventContext($this->name, ClientContext::fromRequest($this->request), method: PasswordSignIn::NAME);

        $this->events->dispatch(new AuthenticationFailed($context, AuthenticationFlow::SIGN_IN, FailureReason::METHOD_NOT_ALLOWED));

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
     * Resolve the identity from the request's API key. `user()` calls this at
     * most once per request, so a rejected key is reported once. A request
     * without a bearer credential attempts nothing and dispatches nothing.
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
        $presented = $this->request->bearerToken();

        if ($presented === null || $presented === '') {
            return null;
        }

        $now       = CarbonImmutable::now()->startOfSecond();
        $outcome   = $this->authenticate($presented, $now);
        $admission = $outcome->admission;

        if ($admission instanceof Refused || $outcome->key === null) {

            $this->events->dispatch($outcome->failure($admission, $this->name, AuthenticationFlow::API_KEY, self::METHOD, ClientContext::fromRequest($this->request)));

            return null;
        }

        $this->bindVerifiedContext($admission->identity, $admission->principal, null, $admission->tenant, self::METHOD, false, $outcome->key->id, $outcome->key->scopes);

        ApiKeyLookup::recordUse($outcome->key, $now);

        return $admission->identity;
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

        /** @var \SineMacula\Laravel\Authentication\Contracts\AudiencePolicy $audience */
        $audience = Container::getInstance()->make(AudiencePolicy::class);

        return (new ApiKeyAuthentication($this->name, self::METHOD, $this->provider, $this->resolver, $audience))->authenticate($public, $secret, $now);
    }
}
