<?php

declare(strict_types = 1);

namespace Tests\Feature\Context;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Auth\Guard;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Context\GuardAuthenticationContexts;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationContexts;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Feature tests of the default authentication contexts.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuardAuthenticationContexts::class)]
final class GuardAuthenticationContextsTest extends TestCase
{
    use InteractsWithSessions;

    /**
     * Freeze the clocks, create the tables and register the routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

        $this->createSessionTables();

        Route::middleware('auth:admin,api')->get('/either/context', static fn (): array => ['application' => Auth::context()?->application]);
        Route::get('/open/context', static fn (): array => ['context' => Auth::context()?->toArray()]);
    }

    /**
     * Release the clocks and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * The default authentication contexts are what the container binds.
     *
     * @return void
     */
    public function testTheDefaultIsBound(): void
    {
        self::assertInstanceOf(GuardAuthenticationContexts::class, app(AuthenticationContexts::class));
        self::assertSame(app(AuthenticationContexts::class), app(AuthenticationContexts::class));
    }

    /**
     * The context is that of the guard the `auth` middleware authenticated
     * with.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheContextIsTheGuardsTheAuthMiddlewareAuthenticatedWith(): void
    {
        $this->seedIdentity();

        $admin = $this->signedIn('admin');
        $api   = $this->signedIn('api');

        $this->fetch('/either/context', $admin)->assertOk()->assertExactJson(['application' => 'admin']);
        $this->fetch('/either/context', $api)->assertOk()->assertExactJson(['application' => 'api']);
        $this->fetch('/open/context')->assertOk()->assertExactJson(['context' => null]);
    }

    /**
     * The contexts hold nothing of their own: one instance answers for the
     * guard and request the container serves when it is asked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheContextsHoldNothingBetweenRequests(): void
    {
        $this->seedIdentity();

        $contexts = new GuardAuthenticationContexts;
        $session  = $this->signedIn('api');

        $this->onRequest($session);

        self::assertSame('api', $contexts->current()?->application);

        $this->onRequest(null);

        self::assertNull($contexts->current());
    }

    /**
     * A refused credential is reported once per request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefusedCredentialIsReportedOncePerRequest(): void
    {
        $this->seedIdentity();

        $token = $this->signedIn('api')->tokens->accessToken->reveal();

        app()->instance('request', Request::create('/context', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token . 'x']));

        Auth::forgetGuards();
        Auth::shouldUse('api');

        $this->recordEvents([AuthenticationFailed::class]);

        foreach ([1, 2] as $ask) {
            self::assertSame([null, null, null, false], [Auth::user(), Auth::context(), Auth::caller(), Auth::guard()->check()], "Ask {$ask}");
        }

        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame([AuthenticationFlow::BEARER, 'api'], [$failed->flow, $failed->context->guard]);
    }

    /**
     * Under a default guard that is not contextual there is no context.
     *
     * @return void
     */
    public function testAGuardThatIsNotContextualHasNoContext(): void
    {
        Auth::extend('plain', static fn (): Guard => \Mockery::mock(Guard::class));
        config()->set('auth.guards.plain', ['driver' => 'plain']);

        Auth::shouldUse('plain');

        self::assertNull((new GuardAuthenticationContexts)->current());
    }

    /**
     * Register the guards and providers.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * A session the seeded identity signed in to on the guard with its
     * password.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(string $guard): SignedInSession
    {
        $session = $this->sessions($guard)->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Request the path, bearing the session's access token when one is given.
     *
     * @param  string  $path
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function fetch(string $path, ?SignedInSession $session = null): TestResponse
    {
        Auth::forgetGuards();

        $client = $session === null ? $this->flushHeaders() : $this->withToken($session->tokens->accessToken->reveal());

        return $client->getJson($path);
    }

    /**
     * Serve a new request, bearing the session's access token when one is
     * given, on the `api` guard as the default.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return void
     */
    private function onRequest(?SignedInSession $session): void
    {
        $server = $session === null ? [] : ['HTTP_AUTHORIZATION' => 'Bearer ' . $session->tokens->accessToken->reveal()];

        app()->instance('request', Request::create('/context', server: $server));

        Auth::forgetGuards();
        Auth::shouldUse('api');
    }
}
