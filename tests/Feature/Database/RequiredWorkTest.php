<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Support\Facades\Exceptions;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Database\RequiredWork;
use Tests\TestCase;

/**
 * Feature tests for the work held for a commit, run once whether through its
 * own closure or once it is due.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RequiredWork::class)]
final class RequiredWorkTest extends TestCase
{
    /**
     * The closure held work returns runs it once.
     *
     * @return void
     */
    public function testTheClosureRunsTheWorkOnce(): void
    {
        /** @var \ArrayObject<int, string> $calls */
        $calls    = new \ArrayObject;
        $required = new RequiredWork(app());
        $run      = $required->hold(static fn (): bool => true, self::recorder($calls, 'work'));

        $run();
        $run();
        $required->runDue();

        self::assertSame(['work'], $calls->getArrayCopy());
    }

    /**
     * Only the work that is due runs, in the order it was held, and each once.
     *
     * @return void
     */
    public function testRunsTheWorkThatIsDueOnceInTheOrderHeld(): void
    {
        /** @var \ArrayObject<int, string> $calls */
        $calls      = new \ArrayObject;
        $exceptions = Exceptions::fake();
        $required   = new RequiredWork(app());
        $due        = new \ArrayObject(['later' => false]);

        $required->hold(static fn (): bool => true, self::recorder($calls, 'first'));
        $required->hold(static fn (): bool => $due['later'] === true, self::recorder($calls, 'later'));
        $ran = $required->hold(static fn (): bool => true, self::recorder($calls, 'ran'));
        $required->hold(static fn (): bool => true, self::recorder($calls, 'last'));

        $ran();
        $required->runDue();

        self::assertSame(['ran', 'first', 'last'], $calls->getArrayCopy());

        $due['later'] = true;

        $required->runDue();
        $required->runDue();

        self::assertSame(['ran', 'first', 'last', 'later'], $calls->getArrayCopy());

        $exceptions->assertNothingReported();
    }

    /**
     * Work that throws through its closure is thrown, while work run once due
     * is reported instead, once, and the rest still runs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWorkThatThrowsIsThrownThroughItsClosureAndReportedOnceDue(): void
    {
        /** @var \ArrayObject<int, string> $calls */
        $calls      = new \ArrayObject;
        $exceptions = Exceptions::fake();
        $required   = new RequiredWork(app());

        $run = $required->hold(static fn (): bool => true, self::thrower('closure'));

        $required->hold(static fn (): bool => true, self::thrower('due'));
        $required->hold(static fn (): bool => true, self::recorder($calls, 'after'));

        try {
            $run();

            self::fail('Expected the work to throw.');
        } catch (\RuntimeException $exception) {
            self::assertSame('closure', $exception->getMessage());
        }

        $run();
        $required->runDue();
        $required->runDue();

        self::assertSame(['after'], $calls->getArrayCopy());
        self::assertSame(['due'], array_map(static fn (\Throwable $exception): string => $exception->getMessage(), $exceptions->reported()));
    }

    /**
     * Work that records its name each time it runs.
     *
     * @param  \ArrayObject<int, string>  $calls
     * @param  string  $name
     * @return \Closure(): void
     */
    private static function recorder(\ArrayObject $calls, string $name): \Closure
    {
        return static function () use ($calls, $name): void {
            $calls->append($name);
        };
    }

    /**
     * Work that throws a runtime exception with the message.
     *
     * @param  string  $message
     * @return \Closure(): void
     */
    private static function thrower(string $message): \Closure
    {
        return static function () use ($message): void {
            throw new \RuntimeException($message);
        };
    }
}
