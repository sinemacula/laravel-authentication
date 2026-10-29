<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
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
}
