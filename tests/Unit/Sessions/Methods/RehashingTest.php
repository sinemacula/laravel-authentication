<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions\Methods;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;

/**
 * Unit tests for the mark that tells an automatic password rehash from a change
 * of password.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Rehashing::class)]
final class RehashingTest extends TestCase
{
    /**
     * The mark is set only while the callback runs, and the callback's result
     * is returned.
     *
     * @return void
     */
    public function testIsRunningOnlyWhileTheCallbackRuns(): void
    {
        $rehashing = new Rehashing;

        self::assertFalse($rehashing->isRunning());

        self::assertSame('rehashed', $rehashing->during(static function () use ($rehashing): string {
            self::assertTrue($rehashing->isRunning());

            return 'rehashed';
        }));

        self::assertFalse($rehashing->isRunning());
    }

    /**
     * A nested rehash does not clear the outer one's mark.
     *
     * @return void
     */
    public function testANestedRehashKeepsTheOuterMark(): void
    {
        $rehashing = new Rehashing;

        $rehashing->during(static function () use ($rehashing): void {

            $rehashing->during(static fn (): bool => $rehashing->isRunning());

            self::assertTrue($rehashing->isRunning());
        });

        self::assertFalse($rehashing->isRunning());
    }

    /**
     * An exception from the callback propagates and still clears the mark, so a
     * long-running worker never keeps it for later work.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExceptionClearsTheMark(): void
    {
        $rehashing = new Rehashing;

        try {
            $rehashing->during(static function (): never {
                throw new \RuntimeException('rehash failed');
            });
        } catch (\RuntimeException $exception) {
            self::assertSame('rehash failed', $exception->getMessage());
        }

        self::assertFalse($rehashing->isRunning());
    }
}
