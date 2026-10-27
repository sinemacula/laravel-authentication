<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Sessions\SessionService;

/**
 * Feature tests for the session service a JWT guard hands out.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
final class JwtGuardTest extends JwtGuardTestCase
{
    /**
     * The guard builds its session service once, from its factory, given the
     * guard itself, and hands out the same service thereafter.
     *
     * @return void
     */
    public function testBuildsItsSessionServiceOnceFromItsFactory(): void
    {
        $app = $this->app;

        assert($app !== null);

        $built    = [];
        $exchange = new RefreshTokenExchange(
            $this->tokens,
            $this->provider,
            $app->make(ConnectionResolverInterface::class),
            static fn (): null => null,
            $this->events,
            $this->resolver,
            self::GUARD_NAME,
        );

        $guard = new JwtGuard(
            self::GUARD_NAME,
            $this->provider,
            $this->resolver,
            $this->events,
            Request::create('/'),
            $this->timebox,
            $this->tokens,
            $exchange,
            function (JwtGuard $guard) use (&$built, $app): SessionService {
                $built[] = $guard;

                return new SessionService($guard, $this->tokens, $app, $app->make(ConnectionResolverInterface::class), static fn (): null => null);
            },
        );

        $sessions = $guard->sessions();

        self::assertSame($sessions, $guard->sessions());
        self::assertSame([$guard], $built);
    }
}
