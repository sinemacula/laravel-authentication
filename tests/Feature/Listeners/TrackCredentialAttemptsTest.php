<?php

declare(strict_types = 1);

namespace Tests\Feature\Listeners;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\OtherDeviceLogout;
use Illuminate\Auth\Events\Validated;
use Illuminate\Auth\GenericUser;
use Illuminate\Support\Facades\Hash;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Listeners\TrackCredentialAttempts;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use Tests\TestCase;

/**
 * Feature tests for the listener that follows Laravel's credential attempts to
 * mark the automatic rehash an attempt runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TrackCredentialAttempts::class)]
final class TrackCredentialAttemptsTest extends TestCase
{
    /**
     * An attempt's `Validated` marks its user on the shared mark, for the
     * password the attempt was made with, so a change of its password is held
     * as the attempt's rehash; each of `Login`, `Authenticated` and `Failed`
     * ends the attempt and drops what it held.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnAttemptsEventsMarkItsUserUntilItEnds(): void
    {
        $rehashing = new Rehashing;
        $listener  = new TrackCredentialAttempts;
        $user      = new GenericUser(['id' => 3, 'password' => Hash::make('secret')]);
        $changes   = [];

        $this->app?->instance(Rehashing::class, $rehashing);

        foreach ([new Login('web', $user, false), new Authenticated('web', $user), new Failed('web', $user, [])] as $end) {

            $listener(new Attempting('web', ['email' => 'ada@example.test', 'password' => 'secret'], false));
            $listener(new Validated('web', $user));

            $rehashing->unlessRehash($user, static function () use (&$changes, $end): void {
                $changes[] = $end::class;
            });

            $listener($end);

            $rehashing->forced($user);
        }

        self::assertSame([], $changes);
    }

    /**
     * `OtherDeviceLogout` runs the change held for its user: the save it
     * follows was the forced rehash of `logoutOtherDevices()`, not the open
     * attempt's.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testOtherDeviceLogoutRunsTheChangeHeldForItsUser(): void
    {
        $rehashing = new Rehashing;
        $listener  = new TrackCredentialAttempts;
        $user      = new GenericUser(['id' => 3, 'password' => Hash::make('secret')]);
        $changes   = new \ArrayObject;

        $this->app?->instance(Rehashing::class, $rehashing);

        $listener(new Attempting('web', ['email' => 'ada@example.test', 'password' => 'secret'], false));
        $listener(new Validated('web', $user));

        $rehashing->unlessRehash($user, static function () use ($changes): void {
            $changes->append(true);
        });

        self::assertCount(0, $changes);

        $listener(new OtherDeviceLogout('console', $user));

        self::assertCount(1, $changes);
    }
}
