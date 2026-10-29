<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Logout;
use Illuminate\Container\Container;
use Illuminate\Contracts\Events\Dispatcher as DispatcherContract;
use Illuminate\Events\Dispatcher;
use Illuminate\Http\Request;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Testing\ActingContext;
use Tests\Unit\Stubs\PlainDeviceFixture;
use Tests\Unit\Stubs\PlainIdentityFixture;
use Tests\Unit\Stubs\PlainPrincipalFixture;
use Tests\Unit\Stubs\PlainTenantFixture;

/**
 * Unit tests for the acting context the testing helpers keep in the container:
 * one context per guard, bound again on each request rebinding after the
 * guard's own reset, ended per guard by `forget()` or a `Logout` for it, tied
 * to the guard instance acted on, and the comparison behind the bound-context
 * assertions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActingContext::class)]
final class ActingContextTest extends TestCase
{
    /** @var \Illuminate\Container\Container The container the guards and the context live in. */
    private Container $container;

    /** @var \Illuminate\Events\Dispatcher The dispatcher the guards report to. */
    private Dispatcher $events;

    /** @var int How many `Authenticated` events have been dispatched. */
    private int $authenticated = 0;

    /**
     * Install a fresh container with a dispatcher, counting `Authenticated`.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->container = new Container;
        $this->events    = new Dispatcher($this->container);

        $this->container->instance(DispatcherContract::class, $this->events);
        $this->container->instance('request', Request::create('/'));

        Container::setInstance($this->container);

        $this->events->listen(Authenticated::class, function (): void {
            $this->authenticated++;
        });
    }

    /**
     * Restore the global container.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Container::setInstance(null);

        parent::tearDown();
    }

    /**
     * The context is created once per container, bound in it, and found again.
     *
     * @return void
     */
    public function testTheContextIsCreatedOncePerContainer(): void
    {
        $context = ActingContext::current();

        self::assertSame($context, ActingContext::current());
        self::assertSame($context, $this->container->make(ActingContext::class));

        $other = new Container;
        $other->instance(DispatcherContract::class, new Dispatcher($other));

        Container::setInstance($other);

        self::assertNotSame($context, ActingContext::current());
    }

    /**
     * Acting binds the context at once and again on every request the guard is
     * rebound to, after the guard's own reset.
     *
     * @return void
     */
    public function testActingBindsNowAndOnEveryRequestRebinding(): void
    {
        $guard     = $this->guard('api');
        $identity  = new PlainIdentityFixture(1);
        $principal = new PlainPrincipalFixture(10, $identity);
        $device    = new PlainDeviceFixture('device-1');

        ActingContext::current()->act($guard, $identity, $principal, $device);

        self::assertSame([$identity, $principal, $device], [$guard->identity(), $guard->principal(), $guard->device()]);
        self::assertSame(1, $this->authenticated);

        $request = Request::create('/me');

        $this->container->instance('request', $request);

        self::assertSame($request, $guard->getRequest());
        self::assertSame([$identity, $principal, $device], [$guard->identity(), $guard->principal(), $guard->device()]);
        self::assertSame(2, $this->authenticated);
    }

    /**
     * Acting again on a guard replaces its context and registers no second
     * rebinding, so each request binds the guard once.
     *
     * @return void
     */
    public function testActingAgainReplacesTheContextAndBindsOncePerRequest(): void
    {
        $guard   = $this->guard('api');
        $first   = new PlainIdentityFixture(1);
        $second  = new PlainIdentityFixture(2);
        $context = ActingContext::current();

        $context->act($guard, $first, new PlainPrincipalFixture(10, $first), null);
        $context->act($guard, $second, new PlainPrincipalFixture(20, $second), null);

        $this->authenticated = 0;

        $this->container->instance('request', Request::create('/me'));

        self::assertSame($second, $guard->identity());
        self::assertSame(1, $this->authenticated);
    }

    /**
     * Each guard keeps its own context, and forgetting one leaves the other
     * acting.
     *
     * @return void
     */
    public function testEachGuardKeepsItsOwnContext(): void
    {
        $api     = $this->guard('api');
        $admin   = $this->guard('admin');
        $ada     = new PlainIdentityFixture(1);
        $grace   = new PlainIdentityFixture(2);
        $context = ActingContext::current();

        $context->act($api, $ada, new PlainPrincipalFixture(10, $ada), null);
        $context->act($admin, $grace, new PlainPrincipalFixture(20, $grace), null);

        $context->forget('api');

        $this->container->instance('request', Request::create('/me'));

        self::assertNull($api->identity());
        self::assertSame($grace, $admin->identity());
    }

    /**
     * A `Logout` for a guard ends acting on that guard only.
     *
     * @return void
     */
    public function testALogoutEndsActingOnItsGuard(): void
    {
        $api     = $this->guard('api');
        $admin   = $this->guard('admin');
        $ada     = new PlainIdentityFixture(1);
        $context = ActingContext::current();

        $context->act($api, $ada, new PlainPrincipalFixture(10, $ada), null);
        $context->act($admin, $ada, new PlainPrincipalFixture(10, $ada), null);

        $this->events->dispatch(new Logout('api', $ada));

        $this->container->instance('request', Request::create('/me'));

        self::assertNull($api->identity());
        self::assertSame($ada, $admin->identity());
    }

    /**
     * Acting is tied to the guard instance acted on: a guard created afresh
     * under the same name is not bound by the earlier instance's rebinding, and
     * acting on the new one stops binding the old one.
     *
     * @return void
     */
    public function testActingIsTiedToTheGuardInstance(): void
    {
        $old     = $this->guard('api');
        $ada     = new PlainIdentityFixture(1);
        $grace   = new PlainIdentityFixture(2);
        $context = ActingContext::current();

        $context->act($old, $ada, new PlainPrincipalFixture(10, $ada), null);

        $new = $this->guard('api');

        $this->container->instance('request', Request::create('/me'));

        self::assertNull($new->identity());

        $context->act($new, $grace, new PlainPrincipalFixture(20, $grace), null);

        $this->container->instance('request', Request::create('/me'));

        self::assertNull($old->identity());
        self::assertSame($grace, $new->identity());
    }

    /**
     * Rows of `[expected, expected identifier, actual, actual identifier,
     * matches]`.
     *
     * @return iterable<string, array{0: ?object, 1: mixed, 2: ?object, 3: mixed, 4: bool}>
     */
    public static function provideComparisons(): iterable
    {
        $ada     = new PlainIdentityFixture(1);
        $unsaved = new PlainIdentityFixture('');

        yield from [
            'nothing expected, nothing bound'      => [null, null, null, null, true],
            'nothing expected, something bound'    => [null, null, $ada, 1, false],
            'something expected, nothing bound'    => [$ada, 1, null, null, false],
            'the same instance'                    => [$ada, 1, $ada, 1, true],
            'the same instance without identifier' => [$unsaved, null, $unsaved, null, true],
            'another instance, same class and id'  => [$ada, 1, new PlainIdentityFixture(1), 1, true],
            'an id of another type'                => [$ada, 1, new PlainIdentityFixture('1'), '1', true],
            'another instance, another id'         => [$ada, 1, new PlainIdentityFixture(2), 2, false],
            'another class, same id'               => [new PlainTenantFixture(1), 1, new PlainPrincipalFixture(1), 1, false],
            'two instances without identifiers'    => [$unsaved, null, new PlainIdentityFixture(''), null, false],
        ];
    }

    /**
     * The bound-context comparison passes for nothing against nothing, the same
     * instance, or the same class with the same identifier, and fails
     * otherwise.
     *
     * @param  ?object  $expected
     * @param  mixed  $expectedIdentifier
     * @param  ?object  $actual
     * @param  mixed  $actualIdentifier
     * @param  bool  $matches
     * @return void
     */
    #[DataProvider('provideComparisons')]
    public function testTheBoundComparison(?object $expected, mixed $expectedIdentifier, ?object $actual, mixed $actualIdentifier, bool $matches): void
    {
        $guard = $this->guard('api');

        try {
            ActingContext::assertBound('identity', $guard, $expected, $expectedIdentifier, $actual, $actualIdentifier);
        } catch (AssertionFailedError) {
            self::assertFalse($matches);

            return;
        }

        self::assertTrue($matches);
    }

    /**
     * A failed comparison names the kind, the guard, the expected subject and
     * the bound one, by class and identifier.
     *
     * @return void
     */
    public function testAFailedComparisonSaysWhatWasExpectedAndWhatIsBound(): void
    {
        $guard = $this->guard('api');

        try {
            ActingContext::assertBound('principal', $guard, new PlainPrincipalFixture(10), 10, null, null);
            self::fail('The comparison passed.');
        } catch (AssertionFailedError $failure) {
            self::assertStringStartsWith(
                sprintf('Expected the principal bound to guard [api] to be %s [10], got none.', PlainPrincipalFixture::class),
                $failure->getMessage(),
            );
        }

        try {
            ActingContext::assertBound('identity', $guard, new PlainIdentityFixture(1), 1, new PlainIdentityFixture(''), null);
            self::fail('The comparison passed.');
        } catch (AssertionFailedError $failure) {
            self::assertStringStartsWith(
                sprintf('Expected the identity bound to guard [api] to be %1$s [1], got %1$s [no identifier].', PlainIdentityFixture::class),
                $failure->getMessage(),
            );
        }
    }

    /**
     * Build a package guard over the container's dispatcher and wire its
     * request rebinding, as the service provider does when it creates one.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authentication\Guards\AbstractGuard
     */
    private function guard(string $name): AbstractGuard
    {
        $provider = self::createStub(IdentityProvider::class);
        $resolver = self::createStub(PrincipalResolver::class);
        $guard    = new class ($name, $provider, $resolver, $this->events, Request::create('/'), new Timebox) extends AbstractGuard {};

        $this->container->refresh('request', $guard, 'setRequest');

        return $guard;
    }
}
