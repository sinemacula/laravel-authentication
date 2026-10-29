<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Auth\SessionGuard;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Support\Facades\Auth;

/**
 * A queued job that signs an identity's other devices out through Laravel's
 * `console` session guard, whose `logoutOtherDevices()` saves a fresh hash of
 * the same password.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LogoutOtherDevicesJob implements ShouldQueue
{
    use Dispatchable, Queueable;

    /**
     * Constructor.
     *
     * @param  int  $identityId
     * @param  string  $password
     */
    public function __construct(

        /** Key of the identity whose other devices are signed out. */
        public int $identityId,

        /** The identity's current password. */
        public string $password,
    ) {}

    /**
     * Bind the identity on the guard and sign its other devices out.
     *
     * @return void
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function handle(): void
    {
        $guard = Auth::guard('console');

        assert($guard instanceof SessionGuard);

        $guard->setUser(IntegrationIdentity::query()->findOrFail($this->identityId));
        $guard->logoutOtherDevices($this->password);
    }
}
