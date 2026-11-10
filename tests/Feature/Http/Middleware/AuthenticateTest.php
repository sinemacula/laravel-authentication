<?php

declare(strict_types = 1);

namespace Tests\Feature\Http\Middleware;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Auth\Middleware\Authenticate as IlluminateAuthenticate;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Http\BearerForms;
use SineMacula\Laravel\Authentication\Http\Middleware\Authenticate;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Feature tests for the package-aware `auth` middleware.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Authenticate::class)]
final class AuthenticateTest extends TestCase
{
    /** @var int Number of times the guest redirect was evaluated. */
    private int $redirects = 0;

    /** @var mixed Guest redirect callback in place before the test. */
    private mixed $previousRedirect = null;

    /**
     * Count guest redirect evaluations.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->previousRedirect = (new \ReflectionProperty(IlluminateAuthenticate::class, 'redirectToCallback'))->getValue();

        IlluminateAuthenticate::redirectUsing(function (): string {
            $this->redirects++;

            return '/login';
        });
    }

    /**
     * Restore the guest redirect callback.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        (new \ReflectionProperty(IlluminateAuthenticate::class, 'redirectToCallback'))->setValue(null, $this->previousRedirect);

        parent::tearDown();
    }

    /**
     * The container hands out the package-aware middleware for Laravel's
     * `Authenticate`.
     *
     * @return void
     */
    public function testContainerResolvesThePackageAwareMiddleware(): void
    {
        self::assertInstanceOf(Authenticate::class, app(IlluminateAuthenticate::class));
    }

    /**
     * A guest on package guards gets an exception naming those guards, with no
     * redirect, and the guest redirect is never evaluated.
     *
     * @return void
     */
    public function testGuestOnPackageGuardsIsRejectedWithoutEvaluatingTheRedirect(): void
    {
        $exception = $this->rejection(['api']);

        self::assertSame('Unauthenticated.', $exception->getMessage());
        self::assertSame(['api'], $exception->guards());
        self::assertSame(0, $this->redirects);
    }

    /**
     * A guest on Laravel's session guard keeps Laravel's redirect.
     *
     * @return void
     */
    public function testGuestOnSessionGuardKeepsLaravelsRedirect(): void
    {
        $exception = $this->rejection(['web']);

        self::assertSame(['web'], $exception->guards());
        self::assertSame('/login', $exception->redirectTo(Request::create('/')));
        self::assertSame(1, $this->redirects);
    }

    /**
     * The middleware records the guards the route lists on the request, in
     * order, before trying them, and `null` for the default guard when the
     * route lists none.
     *
     * @return void
     */
    public function testRecordsTheRouteGuardsOnTheRequest(): void
    {
        $listed = Request::create('/guarded');
        $none   = Request::create('/guarded');

        $this->rejectionOf($listed, ['api', 'web']);
        $this->rejectionOf($none, []);

        self::assertSame(['api', 'web'], $listed->attributes->get(BearerForms::ROUTE_GUARDS));
        self::assertSame([null], $none->attributes->get(BearerForms::ROUTE_GUARDS));
    }

    /**
     * Data provider of a guard a route lists: a package guard and Laravel's
     * session guard.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRouteGuards(): iterable
    {
        yield from [
            'package guard' => ['api'],
            'session guard' => ['web'],
        ];
    }

    /**
     * Something other than a request is passed to Laravel untouched: nothing is
     * recorded, the guards are still tried, and the guest is refused without
     * the guest redirect, which only a request can be given.
     *
     * @param  string  $guard
     * @return void
     */
    #[DataProvider('provideRouteGuards')]
    public function testLeavesSomethingOtherThanARequestUntouched(string $guard): void
    {
        $middleware = app(IlluminateAuthenticate::class);
        $passed     = new \stdClass;

        try {
            $middleware->handle($passed, static fn (): Response => new Response('The guest passed.'), $guard);
        } catch (AuthenticationException $exception) {
            self::assertSame([$guard], $exception->guards());
            self::assertSame([], get_object_vars($passed));
            self::assertSame(0, $this->redirects);

            return;
        }

        self::fail('Expected the guest to be rejected.');
    }

    /**
     * Configure a package `api` guard beside Laravel's `web` session guard.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);

        $config->set('auth.guards.api', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);
    }

    /**
     * Run an HTML guest request through the middleware for the guards and
     * return the exception it raises.
     *
     * @param  array<int, string>  $guards
     * @return \Illuminate\Auth\AuthenticationException
     */
    private function rejection(array $guards): AuthenticationException
    {
        return $this->rejectionOf(Request::create('/guarded', 'GET', server: ['HTTP_ACCEPT' => 'text/html']), $guards);
    }

    /**
     * Run the guest request through the middleware for the guards and return
     * the exception it raises.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  array<int, string>  $guards
     * @return \Illuminate\Auth\AuthenticationException
     */
    private function rejectionOf(Request $request, array $guards): AuthenticationException
    {
        $middleware = app(IlluminateAuthenticate::class);

        try {
            $middleware->handle($request, static fn (): Response => new Response('The guest passed.'), ...$guards);
        } catch (AuthenticationException $exception) {
            return $exception;
        }

        self::fail('Expected the guest to be rejected.');
    }
}
