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
use SineMacula\Laravel\Authentication\Contracts\AuthenticationEvent;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Integration test for the package's custom contextual events.
 *
 * Boots a Testbench application with a `jwt` guard, then exercises the
 * lifecycle points (`attempt()`, bearer authentication, and refresh) where
 * `PrincipalAssigned`, `SessionAuthenticated`, and `Refreshed` are expected to
 * fire. Verifies each event carries the expected payload and that they dispatch
 * via Laravel's standard event dispatcher (so consumers can subscribe via
 * `Event::listen`).
 *
 * The `StubPrincipal` model implements both `Identity` and `Principal` so the
 * 2D-mode resolver returns the identity itself, avoiding the need for a
 * separate principal table.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionAuthenticated::class)]
#[CoversClass(PrincipalAssigned::class)]
#[CoversClass(Refreshed::class)]
#[CoversClass(RefreshTokenExchange::class)]
final class CustomEventsIntegrationTest extends TestCase
{
    use InteractsWithSessionRecords;

    /** @var string The name of the jwt-driven guard under test. */
    private const string JWT_GUARD = 'api';

    /** @var string The email of the seeded test user. */
    private const string USER_EMAIL = 'user@example.test';

    /** @var string The plain-text password of the seeded test user. */
    private const string USER_PASSWORD = 'correct horse battery staple';

    /** @var string A shared test secret for hand-rolled JWTs (32+ bytes). */
    private const string JWT_SECRET = 'test-secret-key-with-at-least-32-bytes!';

    /** @var string Kid the signing secret is registered under. */
    private const string JWT_KID = 'test-kid';

    /** @var \Carbon\Carbon frozen clock shared by Carbon and the JWT library */
    private Carbon $now;

    /**
     * Create the identity table, freeze time, seed a user, and seed a session
     * the jwt guard can bind and refresh against.
     *
     * @return void
     */
    #[\Override]
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
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_principals');

        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A successful attempt through the jwt guard binds a principal and
     * dispatches exactly one `PrincipalAssigned` event carrying the guard name
     * and the resolved principal.
     *
     * @return void
     */
    public function testPrincipalAssignedFiresWhenPrincipalIsBound(): void
    {
        Event::fake([PrincipalAssigned::class]);

        self::assertTrue(Auth::guard(self::JWT_GUARD)->attempt([
            'email'    => self::USER_EMAIL,
            'password' => self::USER_PASSWORD,
        ]));

        Event::assertDispatched(PrincipalAssigned::class, 1);
        Event::assertDispatched(PrincipalAssigned::class, function (PrincipalAssigned $event): bool {

            self::assertSame(self::JWT_GUARD, $event->context->guard);
            self::assertSame(StubPrincipal::class, $event->context->principalType);
            self::assertSame(IdentifierCoercion::stringify(StubPrincipal::query()->where('email', self::USER_EMAIL)->value('id')), $event->context->principalId);

            return true;
        });
    }

    /**
     * A successful JWT authentication whose token carries a `sid` claim binds a
     * session and dispatches exactly one `SessionAuthenticated` event carrying
     * the guard name and session.
     *
     * @return void
     */
    public function testSessionAuthenticatedFiresWhenSessionIsBound(): void
    {
        // Fake the event BEFORE any guard resolution so the guard captures the
        // faked dispatcher in its constructor.
        Event::fake([SessionAuthenticated::class]);

        $user = $this->freshSeededUser();

        $session = new Session;
        $session->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $user->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $user->getMorphClass(),
            'principal_id'         => (string) $user->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash('rotation-' . (string) $user->getKey()), // @phpstan-ignore cast.string
        ])->save();

        $token = $this->encodeAccessToken([
            'sub'       => $user->getKey(),
            'principal' => $user->getKey(),
            'sid'       => $session->getKey(),
        ]);

        $this->swapRequestWithBearerToken($token);

        $resolved = Auth::guard(self::JWT_GUARD)->user();

        self::assertNotNull($resolved);

        Event::assertDispatched(SessionAuthenticated::class, 1);
        Event::assertDispatched(SessionAuthenticated::class, function (SessionAuthenticated $event) use ($session): bool {

            self::assertSame(self::JWT_GUARD, $event->context->guard);
            self::assertSame(IdentifierCoercion::stringify($session->getKey()), $event->context->sessionId);

            return true;
        });
    }

    /**
     * A JWT authentication whose token has no `sid` claim does not dispatch
     * `SessionAuthenticated`.
     *
     * @return void
     */
    public function testSessionAuthenticatedDoesNotFireWhenNoSessionIsBound(): void
    {
        $user = $this->freshSeededUser();

        $token = $this->encodeAccessToken([
            'sub'       => $user->getKey(),
            'principal' => $user->getKey(),
        ]);

        $this->swapRequestWithBearerToken($token);

        Event::fake([SessionAuthenticated::class]);

        self::assertNotNull(Auth::guard(self::JWT_GUARD)->user());

        Event::assertNotDispatched(SessionAuthenticated::class);
    }

    /**
     * A successful refresh through the session service dispatches exactly one
     * `Refreshed` event carrying the guard name and the bound identity.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshedFiresAfterSuccessfulRefresh(): void
    {
        $user = $this->freshSeededUser();

        $plainRotationId = 'stored-rotation-id';

        $session = new Session;
        $session->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $user->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $user->getMorphClass(),
            'principal_id'         => (string) $user->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $refreshToken = JWT::encode(
            [
                'iss'       => self::JWT_ISSUER,
                'aud'       => self::JWT_AUDIENCE,
                'client_id' => self::JWT_GUARD,
                'sid'       => $session->getKey(),
                'jti'       => $plainRotationId,
                'iat'       => $this->now->getTimestamp(),
                'exp'       => $this->now->getTimestamp() + 3600,
            ],
            self::JWT_SECRET,
            'HS256',
            self::JWT_KID,
            ['typ' => TokenType::REFRESH->value],
        );

        Event::fake([Refreshed::class]);

        $guard = app('auth')->guard(self::JWT_GUARD);

        self::assertInstanceOf(JwtGuard::class, $guard);

        $result = GuardSessions::of($guard)->refresh(PresentedRefreshToken::fromBody($refreshToken), self::requestClient($guard->getRequest()))->session?->tokens;

        self::assertInstanceOf(TokenPair::class, $result);

        Event::assertDispatched(Refreshed::class, 1);
        Event::assertDispatched(Refreshed::class, function (Refreshed $event): bool {

            self::assertSame(self::JWT_GUARD, $event->context->guard);
            self::assertSame(StubPrincipal::class, $event->context->identityType);
            self::assertSame(IdentifierCoercion::stringify(StubPrincipal::query()->where('email', self::USER_EMAIL)->value('id')), $event->context->identityId);

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

        self::assertTrue(Auth::guard(self::JWT_GUARD)->attempt([
            'email'    => self::USER_EMAIL,
            'password' => self::USER_PASSWORD,
        ]));

        self::assertCount(1, $captured);
        self::assertSame(self::JWT_GUARD, $captured[0]->context->guard);
    }

    /**
     * One listener registered for the `AuthenticationEvent` contract receives
     * every package event of a flow, and only those: a failed attempt reports
     * its failure, a successful refresh its rotation and then its binds.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testOneListenerOnTheContractReceivesEveryPackageEvent(): void
    {
        $user = $this->freshSeededUser();

        $session = new Session;
        $session->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $user->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => StubPrincipal::class,
            'principal_id'         => (string) $user->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash('stored-rotation-id'),
        ])->save();

        /** @var list<string> $captured */
        $captured = [];

        Event::listen(AuthenticationEvent::class, static function (AuthenticationEvent $event) use (&$captured): void {
            $captured[] = class_basename($event) . ':' . $event->context()->guard;
        });

        self::assertFalse(Auth::guard(self::JWT_GUARD)->attempt(['email' => self::USER_EMAIL, 'password' => 'wrong']));

        $guard  = app('auth')->guard(self::JWT_GUARD);
        $tokens = PackageAuth::jwt(self::JWT_GUARD);

        self::assertInstanceOf(JwtGuard::class, $guard);
        self::assertNotNull($tokens);
        self::assertTrue(
            GuardSessions::of($guard)->refresh(
                PresentedRefreshToken::fromBody($tokens->issueRefreshToken($session, 'stored-rotation-id', $user)->reveal()),
                self::requestClient($guard->getRequest()),
            )->isRefreshed(),
        );

        self::assertSame([
            'AuthenticationFailed:api',
            'Refreshed:api',
            'SignedIn:api',
            'PrincipalAssigned:api',
            'SessionAuthenticated:api',
        ], $captured);
    }

    /**
     * Register the `api` (jwt) guard plus the `api_users` provider and align
     * the package's JWT secret with the test secret so hand-rolled tokens
     * decode cleanly.
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

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.providers.api_users', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);

        $config->set('auth.guards.' . self::JWT_GUARD, [
            'driver'      => 'jwt',
            'provider'    => 'api_users',
            'application' => ['methods' => ['password']],
        ]);

        $config->set('authentication.jwt.keys', [self::JWT_KID => self::JWT_SECRET]);
        $config->set('authentication.jwt.active_kid', self::JWT_KID);
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
     * Encode a JWT access token payload (with `iat`, `exp`, the test issuer,
     * audience and guard, and the `at+jwt` header type) using the shared test
     * secret so the `JwtTokenService::parse()` path accepts it as a valid,
     * unexpired access token; a token that names a session carries a password
     * authentication at its issue time.
     *
     * @param  array<string, mixed>  $claims
     * @return string
     */
    private function encodeAccessToken(array $claims): string
    {
        $now      = $this->now->getTimestamp();
        $defaults = ['jti' => 'access-token-id', 'sub_type' => 'person'];

        if (($claims['sid'] ?? null) !== null) {
            $defaults += ['auth_time' => $now, 'amr' => ['pwd']];
        }

        return JWT::encode(
            [...$defaults, ...$claims, 'iss' => self::JWT_ISSUER, 'aud' => self::JWT_AUDIENCE, 'client_id' => self::JWT_GUARD, 'iat' => $now, 'exp' => $now + (15 * 60)],
            self::JWT_SECRET,
            'HS256',
            self::JWT_KID,
            ['typ' => TokenType::ACCESS->value],
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
