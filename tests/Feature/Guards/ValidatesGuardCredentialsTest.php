<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Guards\Concerns\ValidatesGuardCredentials;
use Tests\Unit\Stubs\StubCredentialGuard;

/**
 * Feature tests for the credential redaction applied to Laravel's `Attempting`
 * and `Failed` events.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ValidatesGuardCredentials::class)]
final class ValidatesGuardCredentialsTest extends AbstractGuardTestCase
{
    /**
     * Every key whose name contains `password`, in any case, is removed and
     * every other key, the identifier included, is kept.
     *
     * @return void
     */
    public function testRedactionRemovesPasswordLikeKeysAndKeepsTheRest(): void
    {
        $redacted = $this->makeCredentialGuard()->redact([
            'email'                 => 'user@example.test',
            'password'              => 'secret',
            'current_password'      => 'secret',
            'password_confirmation' => 'secret',
            'NewPassword'           => 'secret',
            'remember'              => true,
        ]);

        self::assertSame(['email' => 'user@example.test', 'remember' => true], $redacted);
    }

    /**
     * Fragments configured in `redacted_credential_keys` are removed too,
     * case-insensitively, while `password` is still removed and blank or
     * non-string entries are ignored.
     *
     * @return void
     */
    public function testRedactionRemovesConfiguredKeyFragments(): void
    {
        config()->set('authentication.events.redacted_credential_keys', ['Secret', '', 42, 'code']);

        $redacted = $this->makeCredentialGuard()->redact([
            'email'         => 'user@example.test',
            'password'      => 'secret',
            'client_SECRET' => 'secret',
            'otp_code'      => '123456',
            '42'            => 'kept',
        ]);

        self::assertSame(['email' => 'user@example.test', '42' => 'kept'], $redacted);
    }

    /**
     * `Attempting` carries the redacted credentials.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptingEventCarriesRedactedCredentials(): void
    {
        $guard = $this->makeCredentialGuard();

        $this->provider->shouldReceive('retrieveByCredentials')->andReturnNull();

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::on(static fn (mixed $event): bool => $event instanceof Attempting
                && $event->credentials === ['email' => 'user@example.test']));
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::type(Failed::class));

        self::assertFalse($guard->attempt(['email' => 'user@example.test', 'password' => 'secret']));
    }

    /**
     * `Failed` carries the redacted credentials.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testFailedEventCarriesRedactedCredentials(): void
    {
        $guard = $this->makeCredentialGuard();

        $this->provider->shouldReceive('retrieveByCredentials')->andReturnNull();

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::type(Attempting::class));
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::on(static fn (mixed $event): bool => $event instanceof Failed
                && $event->credentials === ['email' => 'user@example.test']));

        self::assertFalse($guard->attempt(['email' => 'user@example.test', 'password' => 'secret']));
    }

    /**
     * Guard subclasses fire both events through the inherited hooks, with the
     * credentials redacted and `Attempting` never advertising remember-me.
     *
     * @return void
     */
    public function testSubclassesFireRedactedEventsThroughTheInheritedHooks(): void
    {
        $guard = $this->makeCredentialGuard();

        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::on(static fn (mixed $event): bool => $event instanceof Attempting
                && $event->guard       === self::GUARD_NAME
                && $event->credentials === ['email' => 'user@example.test']
                && $event->remember    === false));
        $this->events->shouldReceive('dispatch')
            ->once()
            ->with(\Mockery::on(static fn (mixed $event): bool => $event instanceof Failed
                && $event->user        === null
                && $event->credentials === ['email' => 'user@example.test']));

        $guard->announceAttempting(['email' => 'user@example.test', 'password' => 'secret']);
        $guard->announceFailed(null, ['email' => 'user@example.test', 'password' => 'secret']);
    }

    /**
     * Build the credential guard test double over the shared collaborators.
     *
     * @return \Tests\Unit\Stubs\StubCredentialGuard
     */
    private function makeCredentialGuard(): StubCredentialGuard
    {
        return new StubCredentialGuard(self::GUARD_NAME, $this->provider, $this->resolver, $this->events, $this->request, $this->timebox);
    }
}
