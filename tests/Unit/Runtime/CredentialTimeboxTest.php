<?php

declare(strict_types = 1);

namespace Tests\Unit\Runtime;

use Illuminate\Config\Repository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Facade;
use Illuminate\Support\Timebox;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Runtime\CredentialTimebox;
use Tests\Fixtures\Passwords\RecordingTimebox;

/**
 * Unit tests for the credential timebox of a guard: the box is told before
 * every call that it may not return early, so one call's early return never
 * carries over to the next, and each call's budget is read from the
 * configuration then, with the default for a missing, non-positive or
 * unreadable value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CredentialTimebox::class)]
final class CredentialTimeboxTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var int The budget, in microseconds, when none is configured. */
    private const int DEFAULT_BUDGET = 400000;

    /**
     * Forget the configuration behind the facades.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);

        parent::tearDown();
    }

    /**
     * Each call is told first that it may not return early, then runs in the
     * budget configured: the reset comes before the call, every time.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEachCallIsToldItMayNotReturnEarlyBeforeItRuns(): void
    {
        self::configure(['credentials_microseconds' => 650000]);

        $timebox = \Mockery::mock(Timebox::class);

        $run = static fn (\Closure $callback): mixed => $callback($timebox);

        $timebox->shouldReceive('dontReturnEarly')->once()->ordered()->andReturnSelf();
        $timebox->shouldReceive('call')->once()->ordered()->with(\Mockery::type(\Closure::class), 650000)->andReturnUsing($run);
        $timebox->shouldReceive('dontReturnEarly')->once()->ordered()->andReturnSelf();
        $timebox->shouldReceive('call')->once()->ordered()->with(\Mockery::type(\Closure::class), 650000)->andReturnUsing($run);

        $credentials = new CredentialTimebox($timebox);

        self::assertSame('first', $credentials->run(static fn (): string => 'first'));
        self::assertSame('second', $credentials->run(static fn (): string => 'second'));
    }

    /**
     * A check that fails after one that ended the box early waits the box out:
     * the early return is not carried over.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureAfterAnEarlyReturnWaitsTheBoxOut(): void
    {
        self::configure(['credentials_microseconds' => 650000]);

        $box         = new RecordingTimebox;
        $credentials = new CredentialTimebox($box);

        self::assertTrue($credentials->run(static function (Timebox $timebox): bool {
            $timebox->returnEarly();

            return true;
        }));
        self::assertFalse($credentials->run(static fn (): bool => false));

        self::assertSame([true, false], $box->endedEarly);
        self::assertCount(1, $box->waits);
        self::assertGreaterThan(0, $box->waits[0]);
        self::assertLessThanOrEqual(650000, $box->waits[0]);
    }

    /**
     * The callback is handed the timebox it runs in, its result is returned,
     * and an exception it throws propagates.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheCallbackIsHandedTheTimeboxAndItsResultIsReturned(): void
    {
        self::configure(['credentials_microseconds' => 1]);

        $box         = new RecordingTimebox;
        $credentials = new CredentialTimebox($box);
        $received    = null;

        self::assertSame(42, $credentials->run(static function (Timebox $timebox) use (&$received): int {
            $received = $timebox;

            return 42;
        }));
        self::assertSame($box, $received);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('inside the timebox');

        $credentials->run(static function (): never {
            throw new \RuntimeException('inside the timebox');
        });
    }

    /**
     * The budget is read from the configuration on each call, so a change
     * between two calls applies to the second.
     *
     * @return void
     */
    public function testTheBudgetIsReadFromTheConfigurationOnEachCall(): void
    {
        self::configure(['credentials_microseconds' => 650000]);

        $credentials = new CredentialTimebox(new Timebox);

        self::assertSame(650000, $credentials->microseconds());

        config()->set('authentication.timebox.credentials_microseconds', 1);

        self::assertSame(1, $credentials->microseconds());
    }

    /**
     * A missing budget is the default.
     *
     * @return void
     */
    public function testAMissingBudgetIsTheDefault(): void
    {
        self::configure([]);

        self::assertSame(self::DEFAULT_BUDGET, (new CredentialTimebox(new Timebox))->microseconds());
    }

    /**
     * Rows of `[configured, budget]`: a value the budget falls back from, and
     * the default it falls back to.
     *
     * @return iterable<string, array{0: mixed, 1: int}>
     */
    public static function provideFallbacks(): iterable
    {
        yield 'zero' => [0, self::DEFAULT_BUDGET];
        yield 'negative' => [-5, self::DEFAULT_BUDGET];
        yield 'not a number' => ['not-a-number', self::DEFAULT_BUDGET];
        yield 'a list' => [[250000], self::DEFAULT_BUDGET];
    }

    /**
     * A budget that is not positive, or not an integer, falls back to the
     * default, quietly: reading it raises no warning.
     *
     * @param  mixed  $configured
     * @param  int  $budget
     * @return void
     */
    #[DataProvider('provideFallbacks')]
    public function testABudgetThatIsNotAPositiveIntegerFallsBackToTheDefault(mixed $configured, int $budget): void
    {
        self::configure(['credentials_microseconds' => $configured]);

        set_error_handler(static function (int $level, string $message): never {
            throw new \ErrorException($message, 0, $level);
        });

        try {
            self::assertSame($budget, (new CredentialTimebox(new Timebox))->microseconds());
        } finally {
            restore_error_handler();
        }
    }

    /**
     * Without a configuration behind the facade the budget is the default.
     *
     * @return void
     */
    public function testWithoutAConfigurationTheBudgetIsTheDefault(): void
    {
        Facade::clearResolvedInstances();
        Facade::setFacadeApplication(null);

        self::assertSame(self::DEFAULT_BUDGET, (new CredentialTimebox(new Timebox))->microseconds());
    }

    /**
     * Put the timebox settings behind the configuration facade.
     *
     * @param  array<string, mixed>  $settings
     * @return void
     */
    private static function configure(array $settings): void
    {
        // Laravel clears resolved facades on set up, not on tear down, so a
        // Testbench test run just before would otherwise leave its config
        // repository behind the facade.
        Facade::clearResolvedInstances();

        $app = new Application;

        $app->instance('config', new Repository(['authentication' => ['timebox' => $settings]]));

        Facade::setFacadeApplication($app);
    }
}
