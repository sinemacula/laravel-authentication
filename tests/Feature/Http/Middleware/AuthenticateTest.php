<?php

declare(strict_types = 1);

namespace Tests\Feature\Http\Middleware;

use Illuminate\Auth\AuthenticationException;
use Illuminate\Auth\Middleware\Authenticate as IlluminateAuthenticate;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use PHPUnit\Framework\Attributes\CoversClass;
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
        $middleware = app(IlluminateAuthenticate::class);

        $request = Request::create('/guarded', 'GET', server: ['HTTP_ACCEPT' => 'text/html']);

        try {
            $middleware->handle($request, static fn (): Response => new Response('The guest passed.'), ...$guards);
        } catch (AuthenticationException $exception) {
            return $exception;
        }

        self::fail('Expected the guest to be rejected.');
    }
}
