<?php

declare(strict_types=1);

namespace SineMacula\Laravel\Authentication\Guards;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;

/**
 * Stateless HTTP Basic guard.
 *
 * Reads `PHP_AUTH_USER`/`PHP_AUTH_PW` from the active request, runs
 * the resulting credentials through the timing-safe credential
 * validation path on `AbstractGuard`, and resolves the principal via
 * the injected `PrincipalResolver`.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
final class BasicGuard extends AbstractGuard
{
    /**
     * Return the authenticated identity bound to the guard, resolving
     * it from the request's HTTP Basic credentials if necessary.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity|null
     */
    public function user(): ?Identity
    {
        if ($this->identity !== null) {
            return $this->identity;
        }

        $username = $this->request->getUser();
        $password = $this->request->getPassword();

        if ($username === null || $username === '' || $password === null || $password === '') {
            return null;
        }

        $credentials = [
            'email'    => $username,
            'password' => $password,
        ];

        $user = $this->provider->retrieveByCredentials($credentials);

        if (! $this->hasValidCredentials($user, $credentials) || ! $user instanceof Identity) {
            return null;
        }

        $principal = $this->resolver->resolve($user);

        if (! $principal instanceof Principal || ! $principal->isActive()) {
            return null;
        }

        $this->setIdentity($user);
        $this->setPrincipal($principal);

        return $user;
    }
}
