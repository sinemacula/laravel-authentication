<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Illuminate\Database\Eloquent\Model;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Sessions\Concerns\HoldsARotatedSession;
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
#[CoversTrait(HoldsARotatedSession::class)]
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
     * A refreshed outcome read from a source keeps its session and says which
     * source.
     *
     * @return void
     */
    public function testARefreshReadFromASourceKeepsItsSession(): void
    {
        $session   = self::session();
        $refreshed = RefreshResult::refreshed($session)->withSource(RefreshTokenSource::BODY);

        self::assertSame($session, $refreshed->session);
        self::assertSame(RefreshTokenSource::BODY, $refreshed->source);
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
