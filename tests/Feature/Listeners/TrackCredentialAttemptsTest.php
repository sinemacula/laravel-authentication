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
     * password the attempt was made with, so a save that rehashes that password
     * is held as the attempt's rehash; each of `Login`, `Authenticated` and
     * `Failed` for that user ends the attempt, so the next `Attempting` drops
     * what it held, while an end for another user leaves it open.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testAnAttemptsEventsMarkItsUserUntilItEnds(): void
    {
        $rehashing = new Rehashing;
        $listener  = new TrackCredentialAttempts;
        $hash      = Hash::make('secret', ['rounds' => 5]);
        $user      = new GenericUser(['id' => 3, 'password' => Hash::make('secret')]);
        $other     = new GenericUser(['id' => 4]);
        $ends      = [
            [new Login('web', $other, false), new Login('web', $user, false)],
            [new Authenticated('web', $other), new Authenticated('web', $user)],
            [new Failed('web', $other, []), new Failed('web', $user, [])],
        ];

        /** @var \ArrayObject<int, string> $changes */
        $changes = new \ArrayObject;

        $this->app?->instance(Rehashing::class, $rehashing);

        foreach ($ends as [$elsewhere, $end]) {

            $listener(new Attempting('web', ['email' => 'ada@example.test', 'password' => 'secret'], false));
            $listener(new Validated('web', $user));
            $listener($elsewhere);

            $rehashing->unlessRehash($user, $hash, static function () use ($changes, $end): void {
                $changes->append($end::class);
            });

            $listener($end);
            $listener(new Attempting('admin', ['email' => 'grace@example.test', 'password' => 'secret'], false));

            $rehashing->forced($user);
        }

        self::assertSame([], $changes->getArrayCopy());

        $listener(new Attempting('web', ['email' => 'nobody@example.test', 'password' => 'secret'], false));
        $listener(new Failed('web', null, []));
        $listener(new Validated('web', $user));

        $rehashing->unlessRehash($user, $hash, static function () use ($changes): void {
            $changes->append('change');
        });

        self::assertSame(['change'], $changes->getArrayCopy());
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

        $rehashing->unlessRehash($user, Hash::make('secret', ['rounds' => 5]), static function () use ($changes): void {
            $changes->append(true);
        });

        self::assertCount(0, $changes);

        $listener(new OtherDeviceLogout('console', $user));

        self::assertCount(1, $changes);
    }
}
