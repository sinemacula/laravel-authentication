<?php

declare(strict_types = 1);

namespace Tests\Feature\Listeners;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
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
     * password the attempt was made with, and each of `Login`, `Authenticated`
     * and `Failed` ends the attempt.
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

        $this->app?->instance(Rehashing::class, $rehashing);

        foreach ([new Login('web', $user, false), new Authenticated('web', $user), new Failed('web', $user, [])] as $end) {

            $listener(new Attempting('web', ['email' => 'ada@example.test', 'password' => 'secret'], false));
            $listener(new Validated('web', $user));

            self::assertTrue($rehashing->isRunningFor($user));

            $listener($end);

            self::assertFalse($rehashing->isRunningFor($user));
        }
    }
}
