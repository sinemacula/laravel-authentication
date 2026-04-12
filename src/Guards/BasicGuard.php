<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Guards;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;

/**
 * Stateless HTTP Basic guard.
 *
 * Reads `PHP_AUTH_USER`/`PHP_AUTH_PW` from the active request, runs them
 * through the timing-safe credential path on `AbstractGuard`, and resolves the
 * principal via the injected `PrincipalResolver`.
 *
 * Note on webserver config: PHP-FPM behind nginx does NOT populate
 * `PHP_AUTH_USER`/`PHP_AUTH_PW` from the `Authorization` header unless the
 * webserver forwards it (e.g. `fastcgi_pass_header Authorization;`). Without
 * that, this guard sees no credentials.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class BasicGuard extends AbstractGuard
{
    /** @var string Credentials key passed to the identity provider. */
    private readonly string $identifierField;

    /**
     * Constructor.
     *
     * @param  string  $name
     * @param  \SineMacula\Laravel\Authentication\Contracts\IdentityProvider  $provider
     * @param  \SineMacula\Laravel\Authentication\Contracts\PrincipalResolver  $resolver
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @param  \Illuminate\Http\Request  $request
     * @param  \Illuminate\Support\Timebox  $timebox
     * @param  string  $identifierField
     */
    public function __construct(

        // Guard name, as registered under `auth.guards.<name>`.
        string $name,

        // Identity provider used to look up and validate credentials.
        IdentityProvider $provider,

        // Resolver that maps an identity to its acting principal.
        PrincipalResolver $resolver,

        // Event dispatcher for standard and custom auth events.
        Dispatcher $events,

        // Current HTTP request used to extract credentials.
        Request $request,

        // Timebox enforcing uniform elapsed time on the credential path.
        Timebox $timebox,

        // Credentials key passed to the identity provider (defaults to `email`).
        string $identifierField = 'email',

    ) {
        parent::__construct($name, $provider, $resolver, $events, $request, $timebox);

        $this->identifierField = $identifierField === '' ? 'email' : $identifierField;
    }

    /**
     * Return the authenticated identity bound to the guard, resolving it from
     * the request's HTTP Basic credentials if necessary.
     *
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    #[\Override]
    public function user(): ?Identity
    {
        if ($this->identity !== null) {
            return $this->identity;
        }

        $credentials = $this->credentialsFromRequest();

        if ($credentials === null) {
            return null;
        }

        return $this->resolveCredentials($credentials);
    }

    /**
     * Build the credentials array from the request's HTTP Basic
     * username/password, or return `null` when either is missing.
     *
     * @return ?array<string, string>
     */
    private function credentialsFromRequest(): ?array
    {
        $username = $this->request->getUser();
        $password = $this->request->getPassword();

        if ($username === null || $username === '' || $password === null || $password === '') {
            return null;
        }

        return [
            $this->identifierField => $username,
            'password'             => $password,
        ];
    }

    /**
     * Run the credentials through the timing-safe validation path and bind the
     * resolved identity/principal. Returns the bound identity, or `null` after
     * firing `Failed`.
     *
     * Wraps the whole retrieve -> validate -> resolve pipeline in one
     * `Timebox::call()` so elapsed time is uniform regardless of whether the
     * identifier resolves; preserves the timing-safety guarantee against
     * user-enumeration.
     *
     * @param  array<string, string>  $credentials
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function resolveCredentials(#[\SensitiveParameter] array $credentials): ?Identity
    {
        return $this->timebox->call(function (Timebox $timebox) use ($credentials): ?Identity {

            $this->fireAttemptingEvent($credentials);

            $user = $this->provider->retrieveByCredentials($credentials);

            $resolved = $this->validateAndResolvePrincipal($user, $credentials);

            if ($resolved === null) {
                $this->fireFailedEvent($user, $credentials);

                return null;
            }

            [$identity, $principal] = $resolved;

            // user() resolver path went through hasValidCredentials() which
            // already dispatched Validated; bind directly without login() to
            // avoid a double-fire.
            $this->bindAuthenticationLifecycle($identity, $principal);

            $timebox->returnEarly();

            return $identity;
        }, $this->timeboxMicroseconds());
    }

    /**
     * Validate the supplied user/credentials pair and, on success, resolve a
     * principal. Returns the (identity, principal) pair or `null` if any check
     * fails.
     *
     * @formatter:off
     *
     * @param  ?\Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array<string, string>  $credentials
     * @return array{0: \SineMacula\Laravel\Authentication\Contracts\Identity, 1: \SineMacula\Laravel\Authentication\Contracts\Principal}|null
     *
     * @formatter:on
     */
    private function validateAndResolvePrincipal(?Authenticatable $user, #[\SensitiveParameter] array $credentials): ?array
    {
        $credentialsAccepted = $this->hasValidCredentials($user, $credentials)
            && $user instanceof Identity
            && $this->isIdentityActive($user);

        if (!$credentialsAccepted) {
            return null;
        }

        /** @var \SineMacula\Laravel\Authentication\Contracts\Identity $user */
        // safeResolvePrincipal() converts UnresolvableIdentityException into a
        // Failed event so the request surfaces as 401 rather than 500
        $principal = $this->safeResolvePrincipal($user);

        if (!$principal instanceof Principal || !$principal->isActive()) {
            return null;
        }

        return [$user, $principal];
    }
}
