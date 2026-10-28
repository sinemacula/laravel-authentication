<?php

declare(strict_types = 1);

namespace Tests\Integration\Http;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Http\Kernel as HttpKernel;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Http\Middleware\Authenticate;
use SineMacula\Laravel\Authentication\Http\UnauthenticatedResponse;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Guests on a package guard get `401` whatever their `Accept` header, while
 * Laravel's own guards keep the guest redirect.
 *
 * The application here redirects guests to `route('login')`, as Laravel's
 * default application builder does, and defines no login route unless a test
 * adds one, so the package guard cases also prove the redirect is never
 * evaluated for them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Authenticate::class)]
#[CoversClass(UnauthenticatedResponse::class)]
final class UnauthenticatedResponseIntegrationTest extends TestCase
{
    /**
     * Data provider of the `Accept` header a guest may send, `null` for none.
     *
     * @return iterable<string, array{0: ?string}>
     */
    public static function provideAcceptHeaders(): iterable
    {
        yield from [
            'json'    => ['application/json'],
            'html'    => ['text/html'],
            'missing' => [null],
        ];
    }

    /**
     * A guest on a route guarded by a named package guard gets `401`.
     *
     * @param  ?string  $accept
     * @return void
     */
    #[DataProvider('provideAcceptHeaders')]
    public function testGuestOnPackageGuardGetsUnauthorized(?string $accept): void
    {
        Route::middleware('auth:api')->get('/api-only', static fn (): string => 'ok');

        $this->send('/api-only', $accept)
            ->assertUnauthorized()
            ->assertExactJson(['message' => 'Unauthenticated.']);
    }

    /**
     * A guest on a route guarded by the default guard, when that is a package
     * guard, gets `401`.
     *
     * @param  ?string  $accept
     * @return void
     */
    #[DataProvider('provideAcceptHeaders')]
    public function testGuestOnDefaultPackageGuardGetsUnauthorized(?string $accept): void
    {
        config()->set('auth.defaults.guard', 'api');

        Route::middleware('auth')->get('/default', static fn (): string => 'ok');

        $this->send('/default', $accept)
            ->assertUnauthorized()
            ->assertExactJson(['message' => 'Unauthenticated.']);
    }

    /**
     * A guest on a route guarded by Laravel's session guard keeps the guest
     * redirect, and a JSON guest keeps Laravel's JSON `401`.
     *
     * @return void
     */
    public function testGuestOnSessionGuardKeepsLaravelsResponse(): void
    {
        $this->defineLoginRoute();

        Route::middleware('auth:web')->get('/web-only', static fn (): string => 'ok');

        $this->get('/web-only', ['Accept' => 'text/html'])->assertRedirect('/login');
        $this->getJson('/web-only')->assertUnauthorized();
    }

    /**
     * A route that accepts either a session or a package guard is not answered
     * by the package: Laravel's guest redirect applies.
     *
     * @return void
     */
    public function testGuestOnMixedGuardsKeepsLaravelsRedirect(): void
    {
        $this->defineLoginRoute();

        Route::middleware('auth:web,api')->get('/either', static fn (): string => 'ok');

        $this->get('/either', ['Accept' => 'text/html'])->assertRedirect('/login');
    }

    /**
     * Configure a package `api` guard alongside Laravel's `web` session guard.
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

        $config->set('auth.guards.api', [
            'driver'   => 'jwt',
            'provider' => 'identities',
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);
    }

    /**
     * Define the `login` route Laravel's guest redirect points at.
     *
     * @return void
     */
    private function defineLoginRoute(): void
    {
        Route::get('/login', static fn (): string => 'login')->name('login');

        app('router')->getRoutes()->refreshNameLookups();
    }

    /**
     * Send a GET request through the HTTP kernel with the supplied `Accept`
     * header, or with none at all when it is `null`.
     *
     * @param  string  $uri
     * @param  ?string  $accept
     * @return \Illuminate\Testing\TestResponse<\Illuminate\Http\Response>
     */
    private function send(string $uri, ?string $accept): TestResponse
    {
        $request = Request::create($uri);

        $request->headers->remove('Accept');

        if ($accept !== null) {
            $request->headers->set('Accept', $accept);
        }

        $kernel = app(HttpKernel::class);

        $response = $kernel->handle($request);

        $kernel->terminate($request, $response);

        return TestResponse::fromBaseResponse($response, $request);
    }
}
