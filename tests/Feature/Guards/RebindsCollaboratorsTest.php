<?php

declare(strict_types = 1);

namespace Tests\Feature\Guards;

use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\Concerns\RebindsCollaborators;

/**
 * Feature tests for the collaborators a guard follows when the container swaps
 * them: a new request forgets everything resolved for the last one and is
 * resolved again, and a new dispatcher or resolver is used from then on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(RebindsCollaborators::class)]
final class RebindsCollaboratorsTest extends AbstractGuardTestCase
{
    /**
     * A new request clears the bound context and is resolved again on the next
     * access, instead of staying settled by the last request.
     *
     * @return void
     */
    public function testANewRequestForgetsTheLastOneAndIsResolvedAgain(): void
    {
        $this->events->shouldReceive('dispatch');

        $guard = $this->makeCountingGuard();

        $guard->authenticateAs($this->mockIdentity(), $this->mockPrincipal(), $this->mockDevice());

        $next = \Mockery::mock(Request::class);

        self::assertSame($guard, $guard->setRequest($next));
        self::assertFalse($guard->hasUser());
        self::assertSame(0, $guard->resolutions);
        self::assertNull($guard->device());
        self::assertSame(1, $guard->resolutions);
        self::assertSame($next, $guard->getRequest());

        $guard->user();

        self::assertSame(1, $guard->resolutions);
    }

    /**
     * A new dispatcher receives every later event, and the old one none.
     *
     * @return void
     */
    public function testANewDispatcherReceivesTheLaterEvents(): void
    {
        $guard       = $this->makeGuard();
        $replacement = \Mockery::mock(Dispatcher::class);

        $this->events->shouldNotReceive('dispatch');
        $replacement->shouldReceive('dispatch')->times(2);

        self::assertSame($guard, $guard->setDispatcher($replacement));
        self::assertSame($replacement, $guard->getDispatcher());

        $guard->authenticateAs($this->mockIdentity(), $this->mockPrincipal());
    }

    /**
     * A new resolver is the one the guard resolves principals with.
     *
     * @return void
     */
    public function testANewResolverIsUsed(): void
    {
        $guard       = $this->makeGuard();
        $identity    = $this->mockIdentity();
        $principal   = $this->mockPrincipal();
        $replacement = \Mockery::mock(PrincipalResolver::class);

        $this->events->shouldReceive('dispatch');
        $this->resolver->shouldNotReceive('resolve');
        $replacement->shouldReceive('resolve')->once()->with($identity)->andReturn($principal);

        self::assertSame($guard, $guard->setPrincipalResolver($replacement));
        self::assertSame($replacement, $guard->getPrincipalResolver());

        $guard->setUser($identity);

        self::assertSame($principal, $guard->principal());
    }

    /**
     * A guard that counts how often it resolves its request.
     *
     * @return object{resolutions: int}&\SineMacula\Laravel\Authentication\Guards\AbstractGuard
     */
    private function makeCountingGuard(): AbstractGuard
    {
        return new class (self::GUARD_NAME, $this->provider, $this->resolver, $this->events, $this->request, $this->timebox) extends AbstractGuard {
            /** @var int How often the request was resolved. */
            public int $resolutions = 0;

            /**
             * Count the resolution, which finds no credential.
             *
             * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
             */
            #[\Override]
            protected function resolveUserFromRequest(): ?Identity
            {
                $this->resolutions++;

                return null;
            }
        };
    }
}
