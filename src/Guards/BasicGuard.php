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
 * Reads `PHP_AUTH_USER`/`PHP_AUTH_PW` from the active request, runs
 * the resulting credentials through the timing-safe credential
 * validation path on `AbstractGuard`, and resolves the principal via
 * the injected `PrincipalResolver`.
 *
 * Fires the standard `Attempting`, `Validated`, `Failed`, and `Login`
 * events on the bearer-credential resolution path so SIEM pipelines
 * observe the same event shape whether the authentication happens
 * through `attempt()` or a passive `user()` read.
 *
 * Note on webserver config: PHP-FPM behind nginx does NOT populate
 * `PHP_AUTH_USER`/`PHP_AUTH_PW` from the `Authorization` header
 * unless the webserver is explicitly configured to forward it (e.g.
 * `fastcgi_pass_header Authorization;`). If the header is not
 * forwarded, this guard will see no credentials.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class BasicGuard extends AbstractGuard
{
    /** @var string Credentials key passed to the identity provider; configurable via `authentication.credentials.identifier_field`. */
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
        string $name,
        IdentityProvider $provider,
        PrincipalResolver $resolver,
        Dispatcher $events,
        Request $request,
        Timebox $timebox,
        string $identifierField = 'email',
    ) {
        parent::__construct($name, $provider, $resolver, $events, $request, $timebox);

        $this->identifierField = $identifierField === '' ? 'email' : $identifierField;
    }

    /**
     * Return the authenticated identity bound to the guard, resolving
     * it from the request's HTTP Basic credentials if necessary.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|null
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
     * @return array<string, string>|null
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
     * Run the supplied credentials through the timing-safe validation
     * path, fire the standard event sequence, and bind the resolved
     * identity/principal on the guard. Returns the bound identity on
     * success or `null` after firing `Failed` on any failure branch.
     *
     * Wraps the entire `retrieveByCredentials` → `hasValidCredentials`
     * → principal-resolution pipeline in a single `Timebox::call()`
     * so the elapsed time is uniform regardless of whether the
     * supplied identifier resolves to a persisted user — preserves
     * the timing-safety guarantee against user-enumeration attacks.
     *
     * @param  array<string, string>  $credentials
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|null
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

            // BasicGuard's user() resolver path runs through
            // hasValidCredentials() (which already dispatched the
            // Validated event), so we bind directly without going
            // through login() — calling login() would double-fire
            // Validated.
            $this->bindAuthenticationLifecycle($identity, $principal);

            $timebox->returnEarly();

            return $identity;
        }, $this->timeboxMicroseconds());
    }

    /**
     * Validate the supplied user/credentials pair and, on success,
     * resolve a principal. Returns the (identity, principal) pair or
     * `null` if any check fails.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable|null  $user
     * @param  array<string, string>  $credentials
     * @return array{0: \SineMacula\Laravel\Authentication\Contracts\Identity, 1: \SineMacula\Laravel\Authentication\Contracts\Principal}|null
     */
    private function validateAndResolvePrincipal(
        ?Authenticatable $user,
        #[\SensitiveParameter] array $credentials,
    ): ?array {

        $credentialsAccepted = $this->hasValidCredentials($user, $credentials)
            && $user instanceof Identity
            && $this->isIdentityActive($user);

        if (!$credentialsAccepted) {
            return null;
        }

        /** @var \SineMacula\Laravel\Authentication\Contracts\Identity $user */
        // Route through `safeResolvePrincipal()` so a consumer whose
        // identity model implements neither `Principal` nor
        // `HasPrincipals` surfaces as a `Failed` event (→ 401) rather
        // than an uncaught `UnresolvableIdentityException` (→ 500).
        // This matches `JwtGuard::user()` and `AbstractGuard::attempt()`.
        $principal = $this->safeResolvePrincipal($user);

        if (!$principal instanceof Principal || !$principal->isActive()) {
            return null;
        }

        return [$user, $principal];
    }
}
