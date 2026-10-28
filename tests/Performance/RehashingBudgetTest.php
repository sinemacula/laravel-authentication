<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Validated;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
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
     * two hash checks per save of the instance the attempt validated: two for
     * the rehash, one for a new password (the saved hash fails first), and two
     * for a save back to the attempt's password over another; a save through
     * another instance costs none.
     *
     * @return void
     */
    public function testWithAnAttemptForTheUserASaveCostsAtMostTwoHashChecks(): void
    {
        $rehashing = app(Rehashing::class);
        $checks    = [];

        $this->assertQueryBudget(0, 0, function () use ($rehashing, &$checks): void {

            foreach ([[self::PASSWORD, self::PASSWORD], [self::PASSWORD, 'a new password'], ['a new password', self::PASSWORD]] as $key => [$from, $to]) {

                $user = self::user($key, self::PASSWORD);

                Event::dispatch(new Attempting('web', ['email' => 'ada@example.test', 'password' => self::PASSWORD], false));
                Event::dispatch(new Validated('web', $user));

                $previous = (new BcryptHasher(['rounds' => 5]))->make($from);

                $user->forceFill(['password' => app(Hasher::class)->make($to)]);

                $checks[] = $this->checksDuring(static fn () => $rehashing->unlessRehash($user, $previous, static function (): void {}));
            }

            $user = self::user(9, self::PASSWORD);

            Event::dispatch(new Attempting('web', ['email' => 'ada@example.test', 'password' => self::PASSWORD], false));
            Event::dispatch(new Validated('web', $user));

            $checks[] = $this->checksDuring(static fn () => $rehashing->unlessRehash(self::user(9, self::PASSWORD), $user->getAuthPassword(), static function (): void {}));
        });

        self::assertSame([2, 1, 2, 0], $checks);
    }

    /**
     * Rows of `[whether every attempt validates the one instance the command
     * keeps, as a provider that caches its users returns, rather than a fresh
     * instance nothing holds once the next attempt starts]`.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideAbandonedInstances(): iterable
    {
        yield 'a fresh instance each time' => [false];
        yield 'one instance kept throughout' => [true];
    }

    /**
     * Attempts abandoned one after another (an `attemptWhen()` whose callback
     * threw, in a long-running command) are let go of rather than kept for the
     * rest of the command: the guard keeps one attempt, so a later save of
     * another password costs at most the two hash checks of that one.
     *
     * @param  bool  $kept
     * @return void
     */
    #[DataProvider('provideAbandonedInstances')]
    public function testAbandonedAttemptsAreNotKept(bool $kept): void
    {
        $rehashing = app(Rehashing::class);
        $user      = self::user(5, self::PASSWORD);

        for ($attempt = 0; $attempt < 100; $attempt++) {
            Event::dispatch(new Attempting('web', ['email' => 'ada@example.test', 'password' => self::PASSWORD], false));
            Event::dispatch(new Validated('web', $kept ? $user : self::user(5, self::PASSWORD)));
        }

        $user->forceFill(['password' => app(Hasher::class)->make('a new password')]);

        self::assertLessThanOrEqual(2, $this->checksDuring(static fn () => $rehashing->unlessRehash($user, app(Hasher::class)->make(self::PASSWORD), static function (): void {})));
        self::assertCount(1, $this->attemptsOf($rehashing, 'web'));
    }

    /**
     * Attempts for one account abandoned one after another, each after a save
     * taken for its rehash whose change captures the instance saved, as the
     * password-change observer's does, keep one held save and one attempt: a
     * later held save replaces the earlier, which lets its instance go.
     *
     * @return void
     */
    public function testAbandonedAttemptsWithHeldSavesKeepOneForTheAccount(): void
    {
        $rehashing = app(Rehashing::class);

        for ($attempt = 0; $attempt < 100; $attempt++) {

            $user = self::user(5, self::PASSWORD);

            Event::dispatch(new Attempting('web', ['email' => 'ada@example.test', 'password' => self::PASSWORD], false));
            Event::dispatch(new Validated('web', $user));

            $rehashing->unlessRehash($user, app(Hasher::class)->make(self::PASSWORD), static function () use ($user): void {
                $user->getAuthIdentifier();
            });
        }

        unset($user);

        Event::dispatch(new Attempting('web', ['email' => 'ada@example.test', 'password' => self::PASSWORD], false));

        $held = (new \ReflectionProperty(Rehashing::class, 'held'))->getValue($rehashing);

        self::assertIsArray($held);
        self::assertCount(1, $held);
        self::assertCount(2, $this->attemptsOf($rehashing, 'web'));
    }

    /**
     * An attempt still closes at its end once a change of its user's password
     * has run inside it, as when an `attemptWhen()` callback saves a new
     * password and refuses the attempt.
     *
     * @return void
     */
    public function testAnAttemptWhosePasswordChangedStillCloses(): void
    {
        $rehashing = app(Rehashing::class);
        $user      = self::user(5, self::PASSWORD);

        Event::dispatch(new Attempting('web', ['email' => 'ada@example.test', 'password' => self::PASSWORD], false));
        Event::dispatch(new Validated('web', $user));

        $user->forceFill(['password' => app(Hasher::class)->make('a new password')]);

        $rehashing->unlessRehash($user, app(Hasher::class)->make(self::PASSWORD), static function (): void {});

        Event::dispatch(new Failed('web', $user, []));

        self::assertSame([], $this->attemptsOf($rehashing, 'web'));
    }

    /**
     * The attempts the mark keeps open for the guard, read from its state: what
     * a long-running process retains is the budget measured here.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing  $rehashing
     * @param  string  $guard
     * @return array<array-key, mixed>
     */
    private function attemptsOf(Rehashing $rehashing, string $guard): array
    {
        $attempts = (new \ReflectionProperty(Rehashing::class, 'attempts'))->getValue($rehashing);

        self::assertIsArray($attempts);
        self::assertIsArray($attempts[$guard]);

        return $attempts[$guard];
    }

    /**
     * The hash checks made while the callback runs.
     *
     * @param  \Closure(): mixed  $callback
     * @return int
     */
    private function checksDuring(\Closure $callback): int
    {
        $before = $this->checks;

        $callback();

        return $this->checks - $before;
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
