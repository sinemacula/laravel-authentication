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
use SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal;
use SineMacula\Laravel\Authentication\Sessions\SwitchResult;

/**
 * Unit tests for how a switch of principal ends.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SwitchResult::class)]
#[CoversClass(SwitchedPrincipal::class)]
final class SwitchResultTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * A switch that succeeded carries the session, and no reason or wait.
     *
     * @return void
     */
    public function testASwitchedResultCarriesTheSession(): void
    {
        $device  = \Mockery::mock(Model::class, EloquentDevice::class);
        $session = new SignedInSession(\Mockery::mock(Identity::class), \Mockery::mock(Principal::class), $device, new RefreshResult('access', 'refresh'), 'password', false);
        $result  = SwitchResult::switched($session);

        self::assertTrue($result->isSwitched());
        self::assertFalse($result->isFailed());
        self::assertSame($session, $result->session);
        self::assertNull($result->reason);
        self::assertNull($result->retryAfter);
        self::assertNull($result->source);
    }

    /**
     * The same outcome read from a source keeps every part and says which
     * source, without changing the result it came from.
     *
     * @return void
     */
    public function testAResultReadFromASourceSaysWhich(): void
    {
        $limited = SwitchResult::failed(FailureReason::RATE_LIMITED, 30);
        $read    = $limited->from(RefreshTokenSource::COOKIE);

        self::assertNotSame($limited, $read);
        self::assertNull($limited->source);
        self::assertSame(RefreshTokenSource::COOKIE, $read->source);
        self::assertSame(FailureReason::RATE_LIMITED, $read->reason);
        self::assertSame(30, $read->retryAfter);

        $device  = \Mockery::mock(Model::class, EloquentDevice::class);
        $session = new SignedInSession(\Mockery::mock(Identity::class), \Mockery::mock(Principal::class), $device, new RefreshResult('access', 'refresh'), 'password', false);

        self::assertSame($session, SwitchResult::switched($session)->from(RefreshTokenSource::BODY)->session);
    }

    /**
     * A refused switch carries its reason and, when given, the wait.
     *
     * @return void
     */
    public function testAFailedResultCarriesItsReason(): void
    {
        $limited = SwitchResult::failed(FailureReason::RATE_LIMITED, 30);

        self::assertTrue($limited->isFailed());
        self::assertFalse($limited->isSwitched());
        self::assertNull($limited->session);
        self::assertSame(FailureReason::RATE_LIMITED, $limited->reason);
        self::assertSame(30, $limited->retryAfter);

        self::assertNull(SwitchResult::failed(FailureReason::PRINCIPAL_MISMATCH)->retryAfter);
    }

    /**
     * Results are made only through their named constructors.
     *
     * @return void
     */
    public function testTheConstructorIsPrivate(): void
    {
        self::assertTrue((new \ReflectionMethod(SwitchResult::class, '__construct'))->isPrivate());
    }

    /**
     * A switched session keeps the exchanged session and what the device
     * recorded before it.
     *
     * @return void
     */
    public function testASwitchedPrincipalKeepsWhatItWasGiven(): void
    {
        $device    = \Mockery::mock(Model::class, EloquentDevice::class);
        $exchanged = new ExchangedRefresh(\Mockery::mock(Identity::class), \Mockery::mock(Principal::class), $device, new RefreshResult('access', 'refresh'), null, 'password');
        $switched  = new SwitchedPrincipal($exchanged, 'membership', '7', true);

        self::assertSame($exchanged, $switched->session);
        self::assertSame('membership', $switched->previousType);
        self::assertSame('7', $switched->previousId);
        self::assertTrue($switched->switched);
    }
}
