<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions\Methods;

use Illuminate\Auth\GenericUser;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use Tests\Unit\Stubs\PlainIdentityFixture;

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

    /**
     * The package's own rehash marks every user while it runs.
     *
     * @return void
     */
    public function testThePackagesRehashMarksEveryUser(): void
    {
        $rehashing = new Rehashing;

        self::assertFalse($rehashing->isRunningFor(new GenericUser(['id' => 1])));

        self::assertTrue($rehashing->during(static fn (): bool => $rehashing->isRunningFor(new GenericUser(['id' => 2]))));
    }

    /**
     * A guard's attempt marks the user it validated, and no other, from the
     * validation until the attempt ends.
     *
     * @return void
     */
    public function testAnAttemptMarksTheUserItValidatedUntilItEnds(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7]);

        $rehashing->attempting('web');

        self::assertFalse($rehashing->isRunningFor($user));

        $rehashing->validated('web', $user);

        self::assertTrue($rehashing->isRunningFor(new GenericUser(['id' => '7'])));
        self::assertFalse($rehashing->isRunningFor(new GenericUser(['id' => 8])));
        self::assertFalse($rehashing->isRunningFor(new PlainIdentityFixture(7)));
        self::assertFalse($rehashing->isRunning());

        $rehashing->ended('admin');

        self::assertTrue($rehashing->isRunningFor($user));

        $rehashing->ended('web');

        self::assertFalse($rehashing->isRunningFor($user));

        $rehashing->validated('web', $user);

        self::assertFalse($rehashing->isRunningFor($user));
    }

    /**
     * A validation outside an attempt, or by another guard than the one
     * attempting, marks nothing; a new attempt of the guard forgets the user
     * its previous one validated.
     *
     * @return void
     */
    public function testOnlyTheAttemptingGuardsValidationMarks(): void
    {
        $rehashing = new Rehashing;
        $user      = new GenericUser(['id' => 7]);

        $rehashing->validated('web', $user);

        self::assertFalse($rehashing->isRunningFor($user));

        $rehashing->attempting('web');
        $rehashing->validated('admin', $user);

        self::assertFalse($rehashing->isRunningFor($user));

        $rehashing->validated('web', $user);
        $rehashing->attempting('web');

        self::assertFalse($rehashing->isRunningFor($user));
    }
}
