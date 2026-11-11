<?php

declare(strict_types = 1);

namespace Tests\Unit\SessionRecords;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\SessionRecords\SessionGeneration;
use Tests\Unit\Stubs\StubSession;

/**
 * Unit tests for telling two session rows apart by their generations.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionGeneration::class)]
final class SessionGenerationTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string A generation a row records. */
    private const string GENERATION = '01a19701-7c30-71f9-9749-1aed704a4669';

    /**
     * Rows of `[the first row's generation, the second row's, whether they are
     * one session]`.
     *
     * @return iterable<string, array{0: ?string, 1: ?string, 2: bool}>
     */
    public static function provideGenerations(): iterable
    {
        yield from [
            'the same generation'   => [self::GENERATION, self::GENERATION, true],
            'another generation'    => [self::GENERATION, '01a19701-7c30-71f9-9749-1aed704a466a', false],
            'none on the first'     => [null, self::GENERATION, false],
            'none on the second'    => [self::GENERATION, null, false],
            'none on either'        => [null, null, false],
            'none set on the first' => ['', self::GENERATION, false],
        ];
    }

    /**
     * Two rows are one session only when both record the same generation.
     *
     * @param  ?string  $first
     * @param  ?string  $second
     * @param  bool  $same
     * @return void
     */
    #[DataProvider('provideGenerations')]
    public function testTwoRowsAreOneSessionOnlyWithTheSameGeneration(?string $first, ?string $second, bool $same): void
    {
        self::assertSame($same, SessionGeneration::isSame(self::row($first), self::row($second)));
        self::assertSame($same, SessionGeneration::isSame(self::row($second), self::row($first)));
    }

    /**
     * Each row's generation is read from the column its own model names, not
     * from a column of the default name.
     *
     * @return void
     */
    public function testTheGenerationIsReadFromTheColumnTheModelNames(): void
    {
        $renamed = new class extends StubSession {
            /**
             * Column name holding the session's generation.
             *
             * @return string
             */
            #[\Override]
            public function getGenerationName(): string
            {
                return 'lifetime';
            }
        };

        $one   = (clone $renamed)->forceFill(['lifetime' => self::GENERATION, 'generation' => 'one']);
        $other = (clone $renamed)->forceFill(['lifetime' => self::GENERATION, 'generation' => 'other']);

        self::assertTrue(SessionGeneration::isSame($one, $other));
        self::assertTrue(SessionGeneration::isSame($one, self::row(self::GENERATION)));
        self::assertFalse(SessionGeneration::isSame($one, self::row('one')));
    }

    /**
     * Rows of `[the session given, whether its key holds a row, whether the row
     * is that session]`.
     *
     * @return iterable<string, array{0: \Closure(): \SineMacula\Laravel\Authentication\Contracts\Session, 1: bool, 2: bool}>
     */
    public static function provideHeldSessions(): iterable
    {
        yield from [
            'the same generation'        => [static fn (): Session => self::row(self::GENERATION), true, true],
            'another generation'         => [static fn (): Session => self::row('another'), true, false],
            'a key that holds no row'    => [static fn (): Session => self::row(self::GENERATION), false, false],
            'no Eloquent model'          => [static fn (): Session => \Mockery::mock(EloquentSession::class), true, false],
            'no Eloquent session at all' => [static fn (): Session => \Mockery::mock(Session::class), true, false],
        ];
    }

    /**
     * The row under a session's key is that session only when it is an Eloquent
     * session of the row's generation.
     *
     * @param  \Closure(): \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  bool  $stored
     * @param  bool  $held
     * @return void
     */
    #[DataProvider('provideHeldSessions')]
    public function testTheStoredRowIsTheSessionHeldOnlyWhenItsGenerationIs(\Closure $session, bool $stored, bool $held): void
    {
        self::assertSame($held, SessionGeneration::isHeld($session(), $stored ? self::row(self::GENERATION) : null));
    }

    /**
     * The constructor is private.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(SessionGeneration::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);
    }

    /**
     * A session row recording the generation given, or none.
     *
     * @param  ?string  $generation
     * @return \Tests\Unit\Stubs\StubSession
     */
    private static function row(?string $generation): StubSession
    {
        return (new StubSession)->forceFill(['generation' => $generation]);
    }
}
