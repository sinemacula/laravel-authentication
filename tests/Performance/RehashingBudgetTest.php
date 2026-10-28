<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Validated;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Listeners\TrackCredentialAttempts;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use Tests\Integration\Fixtures\IntegrationIdentity;

/**
 * Performance contract for the rehash mark: it runs on every auth event and on
 * every saved password, so it must touch no database, and the hash checks it
 * makes (the costly part) are bounded by the open attempts of the user saved.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Rehashing::class)]
#[CoversClass(TrackCredentialAttempts::class)]
final class RehashingBudgetTest extends PerformanceContractTestCase
{
    /** @var string The password the attempts are made with. */
    private const string PASSWORD = 'secret';

    /** @var int The hash checks made. */
    private int $checks = 0;

    /**
     * Bind a hasher that counts its checks.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $bcrypt = new BcryptHasher(['rounds' => 4]);
        $hasher = \Mockery::mock(Hasher::class);

        $hasher->shouldReceive('make')->andReturnUsing(static fn (string $value): string => $bcrypt->make($value));
        $hasher->shouldReceive('check')->andReturnUsing(function (string $value, mixed $hash) use ($bcrypt): bool {
            $this->checks++;

            return $bcrypt->check($value, $hash);
        });

        app()->instance(Hasher::class, $hasher);
    }

    /**
     * An authenticated request's events, and a saved password with no attempt
     * open for its user, cost no query and no hash check.
     *
     * @return void
     */
    public function testWithNoAttemptForTheUserTheMarkCostsNothing(): void
    {
        $user  = self::user(5, self::PASSWORD);
        $other = self::user(6, self::PASSWORD);
        $runs  = 0;

        $this->assertQueryBudget(0, 0, static function () use ($user, $other, &$runs): void {
            Event::dispatch(new Authenticated('api', $user));

            Event::dispatch(new Attempting('web', ['email' => 'grace@example.test', 'password' => self::PASSWORD], false));
            Event::dispatch(new Validated('web', $other));

            app(Rehashing::class)->unlessRehash($user, $user->getAuthPassword(), static function () use (&$runs): void {
                $runs++;
            });
        });

        self::assertSame(1, $runs);
        self::assertSame(0, $this->checks);
    }

    /**
     * With an attempt open for the user, the mark costs no query and at most
     * two hash checks per save: two for the rehash, one for a new password (the
     * saved hash fails first), and two for a change back to the attempt's
     * password.
     *
     * @return void
     */
    public function testWithAnAttemptForTheUserASaveCostsAtMostTwoHashChecks(): void
    {
        $user      = self::user(5, self::PASSWORD);
        $rehashing = app(Rehashing::class);
        $checks    = [];

        $this->assertQueryBudget(0, 0, function () use ($user, $rehashing, &$checks): void {

            Event::dispatch(new Attempting('web', ['email' => 'ada@example.test', 'password' => self::PASSWORD], false));
            Event::dispatch(new Validated('web', $user));

            foreach ([[self::PASSWORD, self::PASSWORD], [self::PASSWORD, 'a new password'], ['a new password', self::PASSWORD]] as [$from, $to]) {

                $previous = app(Hasher::class)->make($from);

                $user->forceFill(['password' => app(Hasher::class)->make($to)]);

                $before = $this->checks;

                $rehashing->unlessRehash($user, $previous, static function (): void {});

                $checks[] = $this->checks - $before;
            }
        });

        self::assertSame([2, 1, 2], $checks);
    }

    /**
     * An unsaved identity with the key and a hash of the password.
     *
     * @param  int  $key
     * @param  string  $password
     * @return \Tests\Integration\Fixtures\IntegrationIdentity
     */
    private static function user(int $key, string $password): IntegrationIdentity
    {
        return (new IntegrationIdentity)->forceFill(['id' => $key, 'password' => app(Hasher::class)->make($password)]);
    }
}
