<?php

declare(strict_types = 1);

namespace Tests\Feature;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Auth\Middleware\AuthenticatesRequests;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Http\Kernel;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthenticationServiceProvider;
use SineMacula\Laravel\Authentication\Http\Middleware\NoStore;
use SineMacula\Laravel\Authentication\Http\Middleware\UsePendingCredential;
use SineMacula\Laravel\Authentication\Http\Middleware\UseRefreshCredential;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Feature tests for the middleware the provider registers and its place in the
 * HTTP kernel's priority.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AuthenticationServiceProvider::class)]
final class AuthenticationServiceProviderMiddlewareTest extends TestCase
{
    use InteractsWithSessions;

    /** @var list<class-string> The priority list the application sets itself. */
    private const array APPLICATION_PRIORITY = [AuthenticatesRequests::class, SubstituteBindings::class];

    /** @var list<class-string> The priority list once the package has ordered its middleware into it. */
    private const array PACKAGE_PRIORITY = [NoStore::class, AuthenticatesRequests::class, UseRefreshCredential::class, UsePendingCredential::class, SubstituteBindings::class];

    /**
     * Create the tables and a route that lists `auth` before the middleware.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        Route::middleware(['auth:api', 'authentication.no-store'])
            ->get('/recovery-codes', static fn (): JsonResponse => new JsonResponse(['codes' => ['code-one']]));
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * The middleware comes first in the kernel's and router's priority, once,
     * and the credential middleware join just before `SubstituteBindings`.
     *
     * @return void
     */
    public function testTheMiddlewareComesFirstAheadOfTheApplicationsPriority(): void
    {
        $kernel = app()->make(HttpKernel::class);
        $router = app()->make(Router::class);

        self::assertInstanceOf(Kernel::class, $kernel);
        self::assertSame(self::PACKAGE_PRIORITY, $kernel->getMiddlewarePriority());
        self::assertSame(self::PACKAGE_PRIORITY, $router->middlewarePriority);
        self::assertSame(NoStore::class, $router->getMiddleware()['authentication.no-store']);
    }

    /**
     * On a route that lists `auth` before the middleware, the `401` still
     * leaves through it, so it is never stored.
     *
     * @return void
     */
    public function testAnUnauthenticatedResponseLeavesThroughTheMiddleware(): void
    {
        $response = $this->getJson('/recovery-codes')->assertUnauthorized();

        self::assertTrue($response->baseResponse->headers->hasCacheControlDirective('no-store'));
        self::assertSame('no-cache', $response->baseResponse->headers->get('Pragma'));
    }

    /**
     * A kernel resolved again, as a fresh worker resolves it, takes the
     * middleware first again, and only once.
     *
     * @return void
     */
    public function testAKernelResolvedAgainTakesTheMiddlewareFirstAgain(): void
    {
        app()->make(HttpKernel::class);
        app()->forgetInstance(HttpKernel::class);

        $kernel = app()->make(HttpKernel::class);

        self::assertInstanceOf(Kernel::class, $kernel);
        self::assertSame(self::PACKAGE_PRIORITY, $kernel->getMiddlewarePriority());
    }

    /**
     * A kernel that is not the foundation's is left as it is.
     *
     * @return void
     */
    public function testAKernelOfItsOwnIsLeftAsItIs(): void
    {
        $kernel = \Mockery::mock(HttpKernel::class)->shouldIgnoreMissing();

        $kernel->shouldNotReceive('prependToMiddlewarePriority');
        $kernel->shouldNotReceive('addToMiddlewarePriorityBefore');

        app()->forgetInstance(HttpKernel::class);
        app()->singleton(HttpKernel::class, static fn (): HttpKernel => $kernel);

        self::assertSame(spl_object_id($kernel), spl_object_id(app()->make(HttpKernel::class)));
    }

    /**
     * Configure the guards, and an application that sets the kernel's whole
     * priority list itself.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureSessionGuards($app->make(ConfigRepository::class));

        $app->afterResolving(HttpKernel::class, static function (mixed $kernel): void {

            if (!$kernel instanceof Kernel) {
                return;
            }

            $kernel->setMiddlewarePriority(self::APPLICATION_PRIORITY);
        });
    }
}
