<?php

declare(strict_types = 1);

namespace Tests\Integration\Events;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Device as DeviceContract;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Integration test for the package's custom contextual events.
 *
 * Boots a Testbench application with both a `basic` guard (for the
 * principal-assigned paths) and a `jwt` guard (for the device and refresh
 * paths), then exercises the lifecycle points where `PrincipalAssigned`,
 * `DeviceAuthenticated`, and `Refreshed` are expected to fire. Verifies each
 * event carries the expected payload and that they dispatch via Laravel's
 * standard event dispatcher (so consumers can subscribe via `Event::listen`).
 *
 * The `StubPrincipal` model implements both `Identity` and `Principal` so the
 * 2D-mode resolver returns the identity itself, avoiding the need for a
 * separate principal table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversClass(DeviceAuthenticated::class)]
#[CoversClass(PrincipalAssigned::class)]
#[CoversClass(Refreshed::class)]
#[CoversClass(RefreshTokenExchange::class)]
final class CustomEventsIntegrationTest extends TestCase
{
    /** @var string The name of the basic-driven guard under test. */
    private const string BASIC_GUARD = 'cli';

    /** @var string The name of the jwt-driven guard under test. */
    private const string JWT_GUARD = 'api';

    /** @var string The email of the seeded test user. */
    private const string USER_EMAIL = 'user@example.test';

    /** @var string The plain-text password of the seeded test user. */
    private const string USER_PASSWORD = 'correct horse battery staple';

    /** @var string A shared test secret for hand-rolled JWTs (32+ bytes). */
    private const string JWT_SECRET = 'test-secret-key-with-at-least-32-bytes!';

    /** @var \Carbon\Carbon frozen clock shared by Carbon and the JWT library */
    private Carbon $now;

    /**
     * Create the identity table, freeze time, seed a user, and seed a device
     * the jwt guard can bind and refresh against.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {

            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $hasher = app(Hasher::class);

        $user           = new StubPrincipal;
        $user->email    = self::USER_EMAIL;
        $user->password = $hasher->make(self::USER_PASSWORD);
        $user->save();
    }

    /**
     * Drop the seeded identity table and release the frozen clocks.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_principals');

        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A successful attempt through the basic guard binds a principal and
     * dispatches exactly one `PrincipalAssigned` event carrying the guard name
     * and the resolved principal.
     *
     * @return void
     */
    public function testPrincipalAssignedFiresWhenPrincipalIsBound(): void
    {
        Event::fake([PrincipalAssigned::class]);

        self::assertTrue(Auth::guard(self::BASIC_GUARD)->attempt([
            'email'    => self::USER_EMAIL,
            'password' => self::USER_PASSWORD,
        ]));

        Event::assertDispatched(PrincipalAssigned::class, 1);
        Event::assertDispatched(PrincipalAssigned::class, function (PrincipalAssigned $event): bool {

            self::assertSame(self::BASIC_GUARD, $event->guard);
            self::assertInstanceOf(Principal::class, $event->principal);

            $identity = $event->principal->getIdentity();

            self::assertInstanceOf(StubPrincipal::class, $identity);
            self::assertSame(self::USER_EMAIL, $identity->getAttribute('email'));

            return true;
        });
    }

    /**
     * A successful JWT authentication whose token carries a `did` claim binds
     * a device and dispatches exactly one `DeviceAuthenticated` event carrying
     * the guard name and device.
     *
     * @return void
     */
    public function testDeviceAuthenticatedFiresWhenDeviceIsBound(): void
    {
        // Fake the event BEFORE any guard resolution so the guard captures the
        // faked dispatcher in its constructor.
        Event::fake([DeviceAuthenticated::class]);

        $user = $this->freshSeededUser();

        $device = new Device;
        $device->forceFill([
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $user->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'ios',
            'refresh_key'          => RefreshTokenHasher::hash('rotation-' . (string) $user->getKey()), // @phpstan-ignore cast.string
        ])->save();

        $token = $this->encodeAccessToken([
            'sub' => $user->getKey(),
            'pid' => $user->getKey(),
            'did' => $device->getKey(),
        ]);

        $this->swapRequestWithBearerToken($token);

        $resolved = Auth::guard(self::JWT_GUARD)->user();

        self::assertNotNull($resolved);

        Event::assertDispatched(DeviceAuthenticated::class, 1);
        Event::assertDispatched(DeviceAuthenticated::class, function (DeviceAuthenticated $event) use ($device): bool {

            self::assertSame(self::JWT_GUARD, $event->guard);
            self::assertInstanceOf(DeviceContract::class, $event->device);
            self::assertSame($device->getKey(), $event->device->getDeviceIdentifier());

            return true;
        });
    }

    /**
     * A JWT authentication whose token has no `did` claim does not dispatch
     * `DeviceAuthenticated`.
     *
     * @return void
     */
    public function testDeviceAuthenticatedDoesNotFireWhenNoDeviceIsBound(): void
    {
        $user = $this->freshSeededUser();

        $token = $this->encodeAccessToken([
            'sub' => $user->getKey(),
            'pid' => $user->getKey(),
        ]);

        $this->swapRequestWithBearerToken($token);

        Event::fake([DeviceAuthenticated::class]);

        self::assertNotNull(Auth::guard(self::JWT_GUARD)->user());

        Event::assertNotDispatched(DeviceAuthenticated::class);
    }

    /**
     * A successful `JwtGuard::refresh()` exchange dispatches exactly one
     * `Refreshed` event carrying the guard name and the bound identity.
     *
     * @return void
     */
    public function testRefreshedFiresAfterSuccessfulRefresh(): void
    {
        $user = $this->freshSeededUser();

        $plainRotationId = 'stored-rotation-id';

        $device = new Device;
        $device->forceFill([
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $user->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'ios',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $refreshToken = JWT::encode(
            [
                'did' => $device->getKey(),
                'jti' => $plainRotationId,
                'iat' => $this->now->getTimestamp(),
                'exp' => $this->now->getTimestamp() + 3600,
                'typ' => TokenType::REFRESH->value,
            ],
            self::JWT_SECRET,
            'HS256',
        );

        Event::fake([Refreshed::class]);

        $guard = app('auth')->guard(self::JWT_GUARD);

        self::assertInstanceOf(JwtGuard::class, $guard);

        $result = $guard->refresh($refreshToken);

        self::assertInstanceOf(RefreshResult::class, $result);

        Event::assertDispatched(Refreshed::class, 1);
        Event::assertDispatched(Refreshed::class, function (Refreshed $event): bool {

            self::assertSame(self::JWT_GUARD, $event->guard);
            self::assertInstanceOf(Identity::class, $event->identity);
            self::assertInstanceOf(StubPrincipal::class, $event->identity);
            self::assertSame(self::USER_EMAIL, $event->identity->getAttribute('email'));

            return true;
        });
    }

    /**
     * Registering an `Event::listen` callback for `PrincipalAssigned` proves
     * the custom events are observable via Laravel's standard event dispatcher
     * (i.e. not a private pub/sub channel).
     *
     * @return void
     */
    public function testCustomEventsAreObservableViaStandardEventListenRegistration(): void
    {
        /** @var list<\SineMacula\Laravel\Authentication\Events\PrincipalAssigned> $captured */
        $captured = [];

        Event::listen(PrincipalAssigned::class, static function (PrincipalAssigned $event) use (&$captured): void {
            $captured[] = $event;
        });

        self::assertTrue(Auth::guard(self::BASIC_GUARD)->attempt([
            'email'    => self::USER_EMAIL,
            'password' => self::USER_PASSWORD,
        ]));

        self::assertCount(1, $captured);
        self::assertSame(self::BASIC_GUARD, $captured[0]->guard);
    }

    /**
     * Register the `cli` (basic) and `api` (jwt) guards plus the shared
     * `api_users` provider and align the package's JWT secret with the test
     * secret so hand-rolled tokens decode cleanly.
     *
     * @param  mixed  $app
     * @return void
     */
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.providers.api_users', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);

        $config->set('auth.guards.' . self::BASIC_GUARD, [
            'driver'   => 'basic',
            'provider' => 'api_users',
        ]);

        $config->set('auth.guards.' . self::JWT_GUARD, [
            'driver'   => 'jwt',
            'provider' => 'api_users',
        ]);

        $config->set('authentication.jwt.secret', self::JWT_SECRET);
        $config->set('authentication.jwt.algorithm', 'HS256');
        $config->set('authentication.jwt.access_ttl_minutes', 15);
    }

    /**
     * Retrieve the freshly seeded user from the database.
     *
     * @return \Tests\Unit\Stubs\StubPrincipal
     */
    private function freshSeededUser(): StubPrincipal
    {
        return StubPrincipal::query()->where('email', self::USER_EMAIL)->firstOrFail();
    }

    /**
     * Encode a JWT access token payload (with `iat`, `exp`, and `typ =
     * access`) using the shared test secret so the `JwtTokenService::parse()`
     * path accepts it as a valid, unexpired access token.
     *
     * @param  array<string, mixed>  $claims
     * @return string
     */
    private function encodeAccessToken(array $claims): string
    {
        $now = $this->now->getTimestamp();

        return JWT::encode(
            array_merge($claims, [
                'iat' => $now,
                'exp' => $now + (15 * 60),
                'typ' => TokenType::ACCESS->value,
            ]),
            self::JWT_SECRET,
            'HS256',
        );
    }

    /**
     * Rebind the container's `request` singleton with an HTTP request carrying
     * the supplied bearer token so the active `JwtGuard` re-reads it via
     * `$app->refresh('request', ...)`.
     *
     * @param  string  $token
     * @return void
     */
    private function swapRequestWithBearerToken(string $token): void
    {
        $request = Request::create('/test', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $token,
        ]);

        app()->instance('request', $request);
    }
}
