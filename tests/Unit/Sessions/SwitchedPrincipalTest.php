<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Model;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal;

/**
 * Unit tests for a session a switch re-issued the pair of.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SwitchedPrincipal::class)]
final class SwitchedPrincipalTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * It keeps the exchanged session, the principal and tenant the session
     * recorded before the switch, and which of them changed.
     *
     * @return void
     */
    public function testKeepsWhatItWasGiven(): void
    {
        $exchanged = self::exchanged();
        $switched  = new SwitchedPrincipal($exchanged, 'membership', '7', 't-1', true, false);

        self::assertSame($exchanged, $switched->session);
        self::assertSame('membership', $switched->previousType);
        self::assertSame('7', $switched->previousId);
        self::assertSame('t-1', $switched->previousTenantId);
        self::assertTrue($switched->principalChanged);
        self::assertFalse($switched->tenantChanged);
    }

    /**
     * It changed the session when it changed the principal, the tenant or both,
     * and not when it changed neither.
     *
     * @return void
     */
    public function testChangedWhenEitherChanged(): void
    {
        $exchanged = self::exchanged();

        self::assertTrue((new SwitchedPrincipal($exchanged, null, null, null, true, false))->changed());
        self::assertTrue((new SwitchedPrincipal($exchanged, null, null, null, false, true))->changed());
        self::assertTrue((new SwitchedPrincipal($exchanged, null, null, null, true, true))->changed());
        self::assertFalse((new SwitchedPrincipal($exchanged, null, null, null, false, false))->changed());
    }

    /**
     * An exchanged session with a new pair.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\ExchangedRefresh
     */
    private static function exchanged(): ExchangedRefresh
    {
        $record = \Mockery::mock(Model::class, EloquentSession::class);

        return new ExchangedRefresh(
            \Mockery::mock(Identity::class),
            \Mockery::mock(Principal::class),
            $record,
            new TokenPair(new Secret('access'), CarbonImmutable::now()->addMinutes(5), 300, new Secret('refresh')),
            null,
            'password',
        );
    }
}
