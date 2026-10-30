<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use Laravel\Octane\Events\RequestReceived;
use Laravel\Octane\Listeners\FlushAuthenticationState;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\UnauthenticatedResponse;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\ServesRequestsThroughOctane;
use Tests\TestCase;

/**
 * End-to-end tests for the `jwt` guard served by one Laravel Octane worker,
 * through its real request lifecycle: each request runs in a sandbox cloned
 * from the application the worker booted, and Octane's
 * `FlushAuthenticationState` hands the package's auth manager that sandbox and
 * forgets its guards. Nothing one request binds (an identity, a principal, a
 * device, a tenant, a refusal, a sign-in, a logout) is seen by the next, which
 * authenticates from its own token or not at all.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversClass(AuthManager::class)]
#[CoversClass(UnauthenticatedResponse::class)]
final class JwtGuardRequestsTest extends TestCase
{
    use InteractsWithSessions, ServesRequestsThroughOctane;

    /**
     * Freeze the clocks, create the tables, add the routes and boot the worker.
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

        Route::get('/me', static fn (): array => self::contextOf(request()->string('guard', 'api')->value()));

        Route::post('/sign-in', static function (): array {
            $guard   = request()->string('guard', 'api')->value();
            $session = Auth::sessions($guard)->signIn('password', self::credentials(request()->string('email')->value()))->session;

            return [
                'access'  => $session?->tokens->accessToken,
                'context' => self::contextOf($guard),
            ];
        });

        Route::post('/logout', static function (): array {
            Auth::guard('api')->logout();

            return self::contextOf('api');
        });

        Route::middleware('auth:api')->get('/protected', static fn (): array => ['identity' => Auth::guard('api')->id()]);

        $this->bootOctaneWorker();
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
     * One identity's token, then no token, then another identity's: the guest
     * request binds nothing, and the third sees only the second identity, its
     * principal and its device.
     *
     * @return void
     */
    public function testOneIdentitysTokenThenNoneThenAnothers(): void
    {
        [$ada, $first]    = $this->signedIn('ada@example.test');
        [$grace, $second] = $this->signedIn('grace@example.test');

        $this->me($first)->assertJson(['identity' => $ada, 'principal' => $ada]);
        $this->me(null)->assertExactJson(self::guest());
        $this->me($second)->assertExactJson([...self::guest(), 'identity' => $grace, 'principal' => $grace, 'device' => $this->deviceOf($second)]);
    }

    /**
     * A refused token, then a valid one: the refusal is reported once, on its
     * own request, and does not stick to the next.
     *
     * @return void
     */
    public function testARefusedTokenThenAValidOne(): void
    {
        [$ada, $access] = $this->signedIn('ada@example.test');

        $this->recordEvents([AuthenticationFailed::class]);

        $this->me('not-a-jwt')->assertExactJson(self::guest());
        $this->me($access)->assertJson(['identity' => $ada]);

        self::assertSame(FailureReason::TOKEN_INVALID, $this->recordedEvent(AuthenticationFailed::class)->reason);
    }

    /**
     * A sign-in, which binds the guard for the rest of its request, then a
     * request without a token: the second is a guest.
     *
     * @return void
     */
    public function testASignInThenAGuestRequest(): void
    {
        $ada = $this->seedIdentity()->getKey();

        $this->serve(self::octaneRequest('POST', '/sign-in', ['email' => 'ada@example.test']))->assertJson(['context' => ['identity' => $ada]]);
        $this->me(null)->assertExactJson(self::guest());
    }

    /**
     * A logout, which revokes the session and keeps the guard signed out for
     * the rest of its request, then another identity's token: the second is
     * signed in, and the logged-out token stays refused on a later request.
     *
     * @return void
     */
    public function testALogoutThenAnotherIdentitysToken(): void
    {
        [, $first]        = $this->signedIn('ada@example.test');
        [$grace, $second] = $this->signedIn('grace@example.test');

        $this->serve(self::octaneRequest('POST', '/logout', bearer: $first))->assertExactJson(self::guest());
        $this->me($second)->assertJson(['identity' => $grace]);

        $this->recordEvents([AuthenticationFailed::class]);

        $this->me($first)->assertExactJson(self::guest());

        self::assertSame(FailureReason::DEVICE_REVOKED, $this->recordedEvent(AuthenticationFailed::class)->reason);
    }

    /**
     * A member's token, which binds a principal within a tenant, then a 2D
     * identity's token on another guard, then no token on the first: neither
     * later request sees the tenant or the membership.
     *
     * @return void
     */
    public function testATenantThenAnotherGuardThenAGuest(): void
    {
        [, $membership, $tenant] = $this->seedMember();

        $member = $this->serve(self::octaneRequest('POST', '/sign-in', ['email' => 'member@example.test', 'guard' => 'members']))->json('access');

        self::assertIsString($member);

        [$ada, $access] = $this->signedIn('ada@example.test');

        $this->me($member, 'members')->assertJson(['principal' => $membership->getKey(), 'tenant' => $tenant->getKey()]);
        $this->me($access)->assertJson(['identity' => $ada, 'principal' => $ada, 'tenant' => null]);
        $this->me(null, 'members')->assertExactJson(self::guest());
    }

    /**
     * Requests behind `auth:api` answer each by its own token: a guest between
     * two signed-in requests gets the package's `401`, and the signed-in
     * request after it is let through.
     *
     * @return void
     */
    public function testAGuestBetweenSignedInRequestsIsRefused(): void
    {
        [$ada, $first]    = $this->signedIn('ada@example.test');
        [$grace, $second] = $this->signedIn('grace@example.test');

        $this->serve(self::octaneRequest('GET', '/protected', bearer: $first))->assertOk()->assertExactJson(['identity' => $ada]);
        $this->serve(self::octaneRequest('GET', '/protected'))->assertUnauthorized()->assertExactJson(['message' => 'Unauthenticated.']);
        $this->serve(self::octaneRequest('GET', '/protected', bearer: $second))->assertOk()->assertExactJson(['identity' => $grace]);
    }

    /**
     * Without Octane's `FlushAuthenticationState`, the worker's shared auth
     * manager keeps the guard one request resolved, and the next request, with
     * no token, sees the identity the first bound: the isolation the other
     * tests prove is Octane's flush handing the manager each sandbox, which is
     * why it must stay among Octane's listeners.
     *
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    public function testWithoutOctanesAuthenticationFlushTheNextRequestSeesTheLastIdentity(): void
    {
        [$ada, $access] = $this->signedIn('ada@example.test');

        /** @var array<class-string, list<class-string>> $listeners */
        $listeners = config('octane.listeners');
        $events    = $this->app?->make('events');

        self::assertInstanceOf(Dispatcher::class, $events);

        $events->forget(RequestReceived::class);

        foreach (array_diff($listeners[RequestReceived::class], [FlushAuthenticationState::class]) as $listener) {
            $events->listen(RequestReceived::class, $listener);
        }

        $this->me($access)->assertJson(['identity' => $ada]);
        $this->me(null)->assertJson(['identity' => $ada]);
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
     * Seed an identity and sign it in on the `api` guard through the worker.
     *
     * @param  string  $email
     * @return array{0: mixed, 1: string}
     */
    private function signedIn(string $email): array
    {
        $identity = $this->seedIdentity($email)->getKey();
        $access   = $this->serve(self::octaneRequest('POST', '/sign-in', ['email' => $email]))->json('access');

        self::assertIsString($access);

        return [$identity, $access];
    }

    /**
     * Ask the guard who is signed in, with the token or none.
     *
     * @param  ?string  $token
     * @param  string  $guard
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function me(?string $token, string $guard = 'api'): TestResponse
    {
        return $this->serve(self::octaneRequest('GET', '/me', ['guard' => $guard], $token));
    }

    /**
     * The identifier of the device the access token names.
     *
     * @param  string  $access
     * @return mixed
     */
    private function deviceOf(string $access): mixed
    {
        $claims = Auth::manager()->jwt('api')->parse($access);

        self::assertNotNull($claims);

        return $claims[Claims::DEVICE_ID->value] ?? null;
    }

    /**
     * What a guard reports for a guest.
     *
     * @return array{identity: null, principal: null, device: null, tenant: null, scopes: null}
     */
    private static function guest(): array
    {
        return ['identity' => null, 'principal' => null, 'device' => null, 'tenant' => null, 'scopes' => null];
    }
}
