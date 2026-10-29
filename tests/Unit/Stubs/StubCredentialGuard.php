<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Contracts\Auth\Authenticatable;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;

/**
 * Stub guard that extends `AbstractGuard` the way a consumer-defined guard type
 * would, calling the protected credential and lifecycle hooks from a subclass.
 *
 * Pins those hooks as the extension surface: each public method forwards to
 * exactly one protected hook.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubCredentialGuard extends AbstractGuard
{
    /**
     * Bind a resolved context through the inherited
     * `bindAuthenticationLifecycle()` hook.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $device
     * @return void
     */
    public function bindResolvedContext(Identity $identity, Principal $principal, ?Device $device = null): void
    {
        $this->bindAuthenticationLifecycle($identity, $principal, $device);
    }

    /**
     * Bind a context a credential authenticated, with the credential's id and
     * the scopes it grants, through the inherited `bindVerifiedContext()` hook,
     * as a request rather than a sign-in.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $credentialId
     * @param  list<string>  $scopes
     * @return void
     */
    public function bindCredential(Identity $identity, Principal $principal, #[\SensitiveParameter] string $credentialId, array $scopes): void
    {
        $this->bindVerifiedContext($identity, $principal, null, null, 'api_key', false, $credentialId, $scopes);
    }

    /**
     * Clear the bound state through the inherited `clearContextualState()`
     * hook.
     *
     * @return void
     */
    public function clearState(): void
    {
        $this->clearContextualState();
    }

    /**
     * Bind an identity through the inherited `setIdentity()` hook.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return void
     */
    public function bindIdentity(Identity $identity): void
    {
        $this->setIdentity($identity);
    }

    /**
     * Fire `Validated` through the inherited `fireValidatedEvent()` hook.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function announceValidated(Authenticatable $user): void
    {
        $this->fireValidatedEvent($user);
    }

    /**
     * Return the credential timebox budget through the inherited
     * `timeboxMicroseconds()` hook.
     *
     * @return int
     */
    public function credentialTimeboxMicroseconds(): int
    {
        return $this->timeboxMicroseconds();
    }

    /**
     * Redact credentials through the inherited `redactCredentials()` hook.
     *
     * @param  array<string, mixed>  $credentials
     * @return array<string, mixed>
     */
    public function redact(#[\SensitiveParameter] array $credentials): array
    {
        return $this->redactCredentials($credentials);
    }

    /**
     * Fire `Attempting` through the inherited `fireAttemptingEvent()` hook.
     *
     * @param  array<string, mixed>  $credentials
     * @return void
     */
    public function announceAttempting(#[\SensitiveParameter] array $credentials): void
    {
        $this->fireAttemptingEvent($credentials);
    }

    /**
     * Fire `Failed` through the inherited `fireFailedEvent()` hook.
     *
     * @param  ?\Illuminate\Contracts\Auth\Authenticatable  $user
     * @param  array<string, mixed>  $credentials
     * @return void
     */
    public function announceFailed(?Authenticatable $user, #[\SensitiveParameter] array $credentials): void
    {
        $this->fireFailedEvent($user, $credentials);
    }
}
