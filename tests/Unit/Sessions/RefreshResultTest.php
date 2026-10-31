<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Illuminate\Database\Eloquent\Model;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Sessions\RefreshResult;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;

/**
 * Unit tests for how a refresh ends.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshResult::class)]
final class RefreshResultTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * A refresh that succeeded carries the session, and no reason, wait or
     * source.
     *
     * @return void
     */
    public function testARefreshedResultCarriesTheSession(): void
    {
        $session = self::session();
        $result  = RefreshResult::refreshed($session);

        self::assertTrue($result->isRefreshed());
        self::assertFalse($result->isFailed());
        self::assertSame($session, $result->session);
        self::assertNull($result->reason);
        self::assertNull($result->retryAfter);
        self::assertNull($result->source);
    }

    /**
     * A refused refresh carries its reason and, when given, the wait.
     *
     * @return void
     */
    public function testAFailedResultCarriesItsReason(): void
    {
        $limited = RefreshResult::failed(FailureReason::RATE_LIMITED, 30);

        self::assertTrue($limited->isFailed());
        self::assertFalse($limited->isRefreshed());
        self::assertNull($limited->session);
        self::assertSame(FailureReason::RATE_LIMITED, $limited->reason);
        self::assertSame(30, $limited->retryAfter);
        self::assertNull($limited->source);

        self::assertNull(RefreshResult::failed(FailureReason::ROTATION_REUSE)->retryAfter);
    }

    /**
     * The same outcome read from a source keeps every part and says which
     * source, without changing the result it came from.
     *
     * @return void
     */
    public function testAResultReadFromASourceSaysWhich(): void
    {
        $limited = RefreshResult::failed(FailureReason::RATE_LIMITED, 30);
        $read    = $limited->withSource(RefreshTokenSource::COOKIE);

        self::assertNotSame($limited, $read);
        self::assertNull($limited->source);
        self::assertSame(RefreshTokenSource::COOKIE, $read->source);
        self::assertSame(FailureReason::RATE_LIMITED, $read->reason);
        self::assertSame(30, $read->retryAfter);
        self::assertTrue($read->isFailed());

        $session   = self::session();
        $refreshed = RefreshResult::refreshed($session)->withSource(RefreshTokenSource::BODY);

        self::assertSame($session, $refreshed->session);
        self::assertSame(RefreshTokenSource::BODY, $refreshed->source);
        self::assertNull($refreshed->reason);
        self::assertTrue($refreshed->isRefreshed());
    }

    /**
     * Results are made only through their named constructors.
     *
     * @return void
     */
    public function testTheConstructorIsPrivate(): void
    {
        self::assertTrue((new \ReflectionMethod(RefreshResult::class, '__construct'))->isPrivate());
    }

    /**
     * A refreshed session on a device of its own.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     */
    private static function session(): SignedInSession
    {
        $device = \Mockery::mock(Model::class, EloquentDevice::class);

        return new SignedInSession(\Mockery::mock(Identity::class), \Mockery::mock(Principal::class), $device, new TokenPair('access', 'refresh'), 'password', false);
    }
}
