<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;

/**
 * Stub identity provider that looks up a StubPrincipal by primary key.
 *
 * Only `retrieveById` performs a real database lookup; all other methods return
 * null/false/void. Used by integration tests that need a wired provider without
 * the full `ModelProvider` machinery.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubLookupIdentityProvider implements IdentityProvider
{
    /**
     * Retrieve a persisted `StubPrincipal` by its primary key.
     *
     * @param  mixed  $identifier
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    public function retrieveById(mixed $identifier): ?Authenticatable
    {
        $result = StubPrincipal::query()->find($identifier);

        return $result instanceof Authenticatable ? $result : null;
    }

    /**
     * Inert; returns null.
     *
     * @param  mixed  $identifier
     * @param  mixed  $token
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    public function retrieveByToken(mixed $identifier, #[\SensitiveParameter] mixed $token): ?Authenticatable
    {
        return null;
    }

    /**
     * Inert; no-op.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  mixed  $token
     * @return void
     */
    #[\Override]
    public function updateRememberToken(Authenticatable $user, #[\SensitiveParameter] mixed $token): void {}

    /**
     * Inert; returns null.
     *
     * @param  array<array-key, mixed>  $credentials
     * @return ?\Illuminate\Contracts\Auth\Authenticatable
     */
    #[\Override]
    public function retrieveByCredentials(#[\SensitiveParameter] array $credentials): ?Authenticatable
    {
        return null;
    }

    /**
     * Inert; returns false.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array<array-key, mixed>  $credentials
     * @return bool
     */
    #[\Override]
    public function validateCredentials(Authenticatable $user, #[\SensitiveParameter] array $credentials): bool
    {
        return false;
    }

    /**
     * Inert; no-op.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array<array-key, mixed>  $credentials
     * @param  bool  $force
     * @return void
     */
    #[\Override]
    public function rehashPasswordIfRequired(Authenticatable $user, #[\SensitiveParameter] array $credentials, bool $force = false): void {}
}
