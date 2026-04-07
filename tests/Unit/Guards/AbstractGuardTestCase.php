<?php

declare(strict_types = 1);

namespace Tests\Unit\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use Mockery\MockInterface;
use Orchestra\Testbench\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;

/**
 * Shared base case for the AbstractGuard split tests.
 *
 * Owns the collaborator mocks (provider, resolver, dispatcher,
 * request, timebox), the Testbench environment definition, and the
 * `makeGuard()` factory used by every concrete `AbstractGuardTest`
 * variant. Subclasses focus on a single behavioural slice of
 * AbstractGuard so each derived class stays well below the project's
 * 20-method-per-class threshold (radarlint S1448).
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @internal
 */
abstract class AbstractGuardTestCase extends TestCase
{
    use MockeryPHPUnitIntegration;

    /** @var string The guard name forwarded to the concrete test double. */
    protected const string GUARD_NAME = 'test-guard';

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\IdentityProvider The mocked identity provider collaborator. */
    protected MockInterface $provider;

    /** @var \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\PrincipalResolver The mocked principal resolver collaborator. */
    protected MockInterface $resolver;

    /** @var \Illuminate\Contracts\Events\Dispatcher&\Mockery\MockInterface The mocked event dispatcher collaborator. */
    protected MockInterface $events;

    /** @var \Illuminate\Http\Request&\Mockery\MockInterface The mocked HTTP request collaborator. */
    protected MockInterface $request;

    /** @var \Illuminate\Support\Timebox&\Mockery\MockInterface The mocked timebox collaborator. */
    protected MockInterface $timebox;

    /**
     * Build fresh collaborator mocks before each test.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->provider = \Mockery::mock(IdentityProvider::class);
        $this->resolver = \Mockery::mock(PrincipalResolver::class);
        $this->events   = \Mockery::mock(Dispatcher::class);
        $this->request  = \Mockery::mock(Request::class);
        $this->timebox  = \Mockery::mock(Timebox::class);

        // Default: Timebox::call() invokes the callback directly and
        // returns its result so tests exercise the real credential
        // validation path. Tests that need to assert the timebox
        // budget override this expectation.
        $this->timebox->shouldReceive('call')
            ->byDefault()
            ->andReturnUsing(static fn (callable $callback): mixed => $callback(new Timebox));
    }

    /**
     * Define the package config keys that `isInternal()`/`isExternal()`
     * read via the `config()` helper.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        assert($app instanceof \Illuminate\Foundation\Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('laravel-authentication.scopes.internal', 'internal');
        $config->set('laravel-authentication.scopes.external', 'external');
    }

    /**
     * Instantiate a concrete AbstractGuard subclass with the current
     * set of collaborator mocks. The anonymous subclass adds no
     * behaviour beyond forwarding its constructor arguments to the
     * parent.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\AbstractGuard
     */
    protected function makeGuard(): AbstractGuard
    {
        return new class (self::GUARD_NAME, $this->provider, $this->resolver, $this->events, $this->request, $this->timebox) extends AbstractGuard {};
    }

    /**
     * Build a Mockery mock of the Identity contract.
     *
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    protected function mockIdentity(): MockInterface
    {
        return \Mockery::mock(Identity::class);
    }

    /**
     * Build a Mockery mock of the Principal contract whose
     * `isActive()` returns `true` — used by any attempt-path test
     * where the guard calls `isActive()` after the resolver returns.
     *
     * @return \Mockery\MockInterface&\SineMacula\Laravel\Authentication\Contracts\Principal
     */
    protected function mockActivePrincipal(): MockInterface
    {
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('isActive')
            ->byDefault()
            ->andReturnTrue();

        return $principal;
    }
}
