<?php

declare(strict_types = 1);

namespace Tests\Feature\Http\Middleware;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Http\Middleware\NoStore;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Http\AnswerFromCache;
use Tests\Fixtures\Http\CacheForAnHour;
use Tests\TestCase;

/**
 * Feature tests for the `authentication.no-store` middleware: every response of
 * a route that lists it is marked not to be stored, whoever built it and
 * however the request ended.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NoStore::class)]
final class NoStoreTest extends TestCase
{
    use InteractsWithSessions;

    /**
     * Register routes that hand out secrets of other packages. The routes that
     * list a middleware the kernel's priority knows list it before this one, so
     * only the priority puts this one outside it; an application's own
     * middleware is wrapped only when the route lists this one first.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        Route::middleware(['authentication.no-store', CacheForAnHour::class])
            ->get('/factor-secret', static fn (): JsonResponse => new JsonResponse(['secret' => 'factor-secret-value']));

        Route::middleware(['auth:api', 'authentication.no-store'])
            ->get('/recovery-codes', static fn (): JsonResponse => new JsonResponse(['codes' => ['code-one']]));

        Route::middleware([SubstituteBindings::class, 'authentication.no-store'])
            ->get('/sessions/{session}', static fn (Session $session): JsonResponse => new JsonResponse(['id' => $session->getKey()]));

        Route::middleware(['authentication.no-store', AnswerFromCache::class])
            ->get('/answered-early', static fn (): JsonResponse => new JsonResponse(['unreached' => true]));

        Route::middleware(['authentication.no-store', CacheForAnHour::class])
            ->get('/failing', static function (): never {
                throw new \RuntimeException('a bug in the controller');
            });

        Route::middleware([CacheForAnHour::class, 'authentication.no-store'])
            ->get('/cached-outside', static fn (): JsonResponse => new JsonResponse(['public' => true]));

        Route::middleware(CacheForAnHour::class)
            ->get('/cacheable', static fn (): JsonResponse => new JsonResponse(['public' => true]));
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
     * The middleware marks the response its route gives not to be stored,
     * replacing the caching another middleware allowed, and passes the response
     * on otherwise untouched.
     *
     * @return void
     */
    public function testTheResponseOfTheRouteIsNeverStored(): void
    {
        $response = $this->getJson('/factor-secret')->assertOk()->assertExactJson(['secret' => 'factor-secret-value']);

        self::assertNoStore($response);
    }

    /**
     * The `401` of `auth`, listed before the middleware, leaves through it too,
     * since the kernel's priority puts it outside every sorted middleware.
     *
     * @return void
     */
    public function testAnUnauthenticatedResponseIsNeverStored(): void
    {
        self::assertNoStore($this->getJson('/recovery-codes')->assertUnauthorized());
    }

    /**
     * A route binding that finds nothing answers `404`, never stored.
     *
     * @return void
     */
    public function testARefusedBindingIsNeverStored(): void
    {
        self::assertNoStore($this->getJson('/sessions/missing-session')->assertNotFound());
    }

    /**
     * A later middleware that answers the request itself, letting its answer be
     * cached, is still marked not to be stored.
     *
     * @return void
     */
    public function testAnEarlyAnswerOfALaterMiddlewareIsNeverStored(): void
    {
        $response = $this->getJson('/answered-early')->assertOk()->assertExactJson(['recovery_codes' => ['early-recovery-code']]);

        self::assertNoStore($response);
    }

    /**
     * An error the controller raised is rendered and marked not to be stored.
     *
     * @return void
     */
    public function testAnErrorResponseIsNeverStored(): void
    {
        $this->withoutExceptionHandling([\RuntimeException::class]);

        self::assertNoStore($this->getJson('/failing')->assertStatus(500));
    }

    /**
     * The kernel sorts only the middleware its priority knows, so an
     * application's own middleware the route lists before this one stays
     * outside it and may allow caching again: the documented limit.
     *
     * @return void
     */
    public function testAnApplicationMiddlewareListedBeforeItStaysOutsideIt(): void
    {
        $headers = $this->getJson('/cached-outside')->assertOk()->baseResponse->headers;

        self::assertTrue($headers->hasCacheControlDirective('no-store'));
        self::assertTrue($headers->hasCacheControlDirective('public'));
        self::assertSame('3600', $headers->getCacheControlDirective('max-age'));
    }

    /**
     * A route that does not list the middleware keeps its own caching: the
     * middleware is opt-in per route.
     *
     * @return void
     */
    public function testARouteWithoutTheMiddlewareKeepsItsCaching(): void
    {
        $response = $this->getJson('/cacheable')->assertOk();

        self::assertTrue($response->baseResponse->headers->hasCacheControlDirective('public'));
        self::assertFalse($response->baseResponse->headers->hasCacheControlDirective('no-store'));
    }

    /**
     * Called directly, the middleware passes the request on and marks the
     * response it gets back, whatever it is.
     *
     * @return void
     */
    public function testHandleMarksTheResponseItIsGiven(): void
    {
        $request  = Request::create('/');
        $response = (new Response('body'))->setPublic()->setMaxAge(60);
        $handled  = (new NoStore)->handle($request, static fn (Request $given): Response => $given === $request ? $response : new Response('wrong'));

        self::assertSame($response, $handled);
        self::assertSame('body', $handled->getContent());
        self::assertTrue($handled->headers->hasCacheControlDirective('no-store'));
        self::assertFalse($handled->headers->hasCacheControlDirective('max-age'));
    }

    /**
     * Configure the guards.
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
    }

    /**
     * Assert the response may not be stored, and allows no caching at all.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @return void
     */
    private static function assertNoStore(TestResponse $response): void
    {
        $headers = $response->baseResponse->headers;

        self::assertTrue($headers->hasCacheControlDirective('no-store'));
        self::assertFalse($headers->hasCacheControlDirective('public'));
        self::assertFalse($headers->hasCacheControlDirective('max-age'));
        self::assertFalse($headers->hasCacheControlDirective('s-maxage'));
        self::assertSame('no-cache', $headers->get('Pragma'));
    }
}
