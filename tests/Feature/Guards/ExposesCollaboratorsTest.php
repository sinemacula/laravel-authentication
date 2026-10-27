<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Guards\Concerns\ExposesCollaborators;

/**
 * Feature tests for the read access a guard gives the code that signs in
 * through it: each collaborator as the guard holds it now, rebinds included,
 * and the guard's credential timebox.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ExposesCollaborators::class)]
final class ExposesCollaboratorsTest extends AbstractGuardTestCase
{
    /**
     * The getters return the collaborators the guard was built with.
     *
     * @return void
     */
    public function testExposesTheCollaboratorsTheGuardHolds(): void
    {
        $guard = $this->makeGuard();

        self::assertSame($this->provider, $guard->getProvider());
        self::assertSame($this->resolver, $guard->getPrincipalResolver());
        self::assertSame($this->events, $guard->getDispatcher());
        self::assertSame($this->request, $guard->getRequest());
    }

    /**
     * After the guard is rebound to another request, dispatcher or resolver,
     * the getters return the new one.
     *
     * @return void
     */
    public function testFollowsTheGuardsRebinds(): void
    {
        $guard      = $this->makeGuard();
        $request    = Request::create('/next');
        $dispatcher = \Mockery::mock(Dispatcher::class);
        $resolver   = \Mockery::mock(PrincipalResolver::class);

        $guard->setRequest($request)->setDispatcher($dispatcher)->setPrincipalResolver($resolver);

        self::assertSame($request, $guard->getRequest());
        self::assertSame($dispatcher, $guard->getDispatcher());
        self::assertSame($resolver, $guard->getPrincipalResolver());
    }

    /**
     * The callback runs inside the guard's timebox with the configured
     * credential budget, and its result is returned.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRunsTheCallbackInTheCredentialTimebox(): void
    {
        config()->set('authentication.timebox.credentials_microseconds', 750000);

        $given = null;

        $this->timebox = \Mockery::mock(Timebox::class);
        $this->timebox->shouldReceive('call')
            ->once()
            ->with(\Mockery::type(\Closure::class), 750000)
            ->andReturnUsing(static function (\Closure $callback) use (&$given): mixed {
                $given = new Timebox;

                return $callback($given);
            });

        $received = null;

        $result = $this->makeGuard()->callInCredentialTimebox(static function (Timebox $timebox) use (&$received): string {
            $received = $timebox;

            return 'outcome';
        });

        self::assertSame('outcome', $result);
        self::assertSame($given, $received);
    }
}
