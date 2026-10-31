<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions\Concerns;

use Illuminate\Database\Eloquent\Model;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Sessions\Concerns\HoldsARotatedSession;
use SineMacula\Laravel\Authentication\Sessions\RefreshResult;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SwitchResult;

/**
 * Unit tests for the shape a refresh's and a switch's results share: a refusal
 * with its reason and wait, a copy that says where the refresh token was read
 * from, and whether the call failed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshResult::class)]
#[CoversClass(SwitchResult::class)]
#[CoversTrait(HoldsARotatedSession::class)]
final class HoldsARotatedSessionTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Rows of `[the refusal of the result, its success for a session]`: the
     * refresh's and the switch's.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\SineMacula\Laravel\Authentication\Events\Enums\FailureReason, ?int): (\SineMacula\Laravel\Authentication\Sessions\RefreshResult|\SineMacula\Laravel\Authentication\Sessions\SwitchResult), 1: \Closure(\SineMacula\Laravel\Authentication\Sessions\SignedInSession): (\SineMacula\Laravel\Authentication\Sessions\RefreshResult|\SineMacula\Laravel\Authentication\Sessions\SwitchResult)}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideResults(): iterable
    {
        yield 'a refresh' => [RefreshResult::failed(...), RefreshResult::refreshed(...)];

        yield 'a switch' => [SwitchResult::failed(...), SwitchResult::switched(...)];
    }

    /**
     * A refused call carries its reason and, when given, the wait, and no
     * session or source, and did not succeed; a call that succeeded did, and
     * did not fail.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Events\Enums\FailureReason, ?int): (\SineMacula\Laravel\Authentication\Sessions\RefreshResult|\SineMacula\Laravel\Authentication\Sessions\SwitchResult)  $failed
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SignedInSession): (\SineMacula\Laravel\Authentication\Sessions\RefreshResult|\SineMacula\Laravel\Authentication\Sessions\SwitchResult)  $succeeded
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    #[DataProvider('provideResults')]
    public function testAFailedResultCarriesItsReason(\Closure $failed, \Closure $succeeded): void
    {
        $limited = $failed(FailureReason::RATE_LIMITED, 30);

        self::assertTrue($limited->isFailed());
        self::assertNull($limited->session);
        self::assertSame(FailureReason::RATE_LIMITED, $limited->reason);
        self::assertSame(30, $limited->retryAfter);
        self::assertNull($limited->source);

        self::assertNull($failed(FailureReason::ROTATION_REUSE, null)->retryAfter);
        self::assertFalse(self::succeeded($limited));

        $session   = self::session();
        $refreshed = $succeeded($session);

        self::assertTrue(self::succeeded($refreshed));
        self::assertFalse($refreshed->isFailed());
        self::assertSame($session, $refreshed->session);
    }

    /**
     * The same outcome read from a source keeps every part and says which
     * source, without changing the result it came from.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\SineMacula\Laravel\Authentication\Events\Enums\FailureReason, ?int): (\SineMacula\Laravel\Authentication\Sessions\RefreshResult|\SineMacula\Laravel\Authentication\Sessions\SwitchResult)  $failed
     * @param  \Closure(\SineMacula\Laravel\Authentication\Sessions\SignedInSession): (\SineMacula\Laravel\Authentication\Sessions\RefreshResult|\SineMacula\Laravel\Authentication\Sessions\SwitchResult)  $succeeded
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    #[DataProvider('provideResults')]
    public function testAResultReadFromASourceSaysWhich(\Closure $failed, \Closure $succeeded): void
    {
        $limited = $failed(FailureReason::RATE_LIMITED, 30);
        $read    = $limited->withSource(RefreshTokenSource::COOKIE);

        self::assertNotSame($limited, $read);
        self::assertInstanceOf($limited::class, $read);
        self::assertNull($limited->source);
        self::assertSame(RefreshTokenSource::COOKIE, $read->source);
        self::assertSame(FailureReason::RATE_LIMITED, $read->reason);
        self::assertSame(30, $read->retryAfter);
        self::assertTrue($read->isFailed());
        self::assertFalse(self::succeeded($read));

        $session = self::session();
        $body    = $succeeded($session)->withSource(RefreshTokenSource::BODY);

        self::assertSame($session, $body->session);
        self::assertSame(RefreshTokenSource::BODY, $body->source);
        self::assertNull($body->reason);
        self::assertFalse($body->isFailed());
        self::assertTrue(self::succeeded($body));
    }

    /**
     * Whether the result says, in its own name, that the call succeeded.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\RefreshResult|\SineMacula\Laravel\Authentication\Sessions\SwitchResult  $result
     * @return bool
     */
    private static function succeeded(RefreshResult|SwitchResult $result): bool
    {
        return $result instanceof RefreshResult ? $result->isRefreshed() : $result->isSwitched();
    }

    /**
     * A session on a device of its own.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     */
    private static function session(): SignedInSession
    {
        $device = \Mockery::mock(Model::class, EloquentDevice::class);

        return new SignedInSession(\Mockery::mock(Identity::class), \Mockery::mock(Principal::class), $device, new TokenPair('access', 'refresh'), 'password', false);
    }
}
