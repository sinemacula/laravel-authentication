<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Auth\SessionGuard;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Foundation\Application;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Listeners\Concerns\RevokesOnceCommitted;
use SineMacula\Laravel\Authentication\Listeners\RevokeSessionsOnDeactivation;
use SineMacula\Laravel\Authentication\Listeners\RevokeSessionsOnPasswordChange;
use SineMacula\Laravel\Authentication\Listeners\RevokeSessionsOnPasswordReset;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\AttributeObservedIdentity;
use Tests\Integration\Fixtures\EloquentIdentityProvider;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * End-to-end tests of the optional security-change listeners against a real
 * database.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevokeSessionsOnPasswordChange::class)]
#[CoversClass(RevokeSessionsOnPasswordReset::class)]
#[CoversClass(RevokeSessionsOnDeactivation::class)]
#[CoversTrait(RevokesOnceCommitted::class)]
final class SecurityChangeEndToEndTest extends TestCase
{
    use InteractsWithSessions;

    /**
     * Freeze the clocks, create the tables, register the routes and the
     * listeners.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClocksTo(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();

        Route::middleware('auth:api')->get('/me', static fn (): array => ['identity' => Auth::id()]);

        Route::post('/refresh', static function (Request $request): array {

            $guard = app('auth')->guard('api');

            assert($guard instanceof JwtGuard);

            return ['refreshed' => self::sessionsOf($guard)->refresh(
                PresentedRefreshToken::fromBody($request->string('refresh_token')->toString()),
                self::requestClient(),
            )->isRefreshed()];
        });

        IntegrationIdentity::observe([RevokeSessionsOnPasswordChange::class, RevokeSessionsOnDeactivation::class]);

        Event::listen(PasswordReset::class, RevokeSessionsOnPasswordReset::class);
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
     * A changed password ends the session once its transaction commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangedPasswordEndsTheSessionOnceCommitted(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn();

        DB::transaction(function () use ($identity, $session): void {

            $identity->forceFill(['password' => app(Hasher::class)->make('a new password')])->save();

            $this->bearer($session->tokens->accessToken->reveal())->assertOk();
        });

        $this->assertSessionEnded($session);

        self::assertTrue($this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'a new password'], self::requestContext())->isSignedIn());
    }

    /**
     * Changing the password back inside the automatic rehash ends the session
     * started between.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeBackInsideTheAutomaticRehashEndsTheSessionStartedBetween(): void
    {
        $identity = $this->seedIdentity();
        $before   = $this->signIn();

        DB::table('integration_identities')->update(['password' => (new BcryptHasher(['rounds' => 5]))->make(self::PASSWORD)]);

        Auth::provider('evented', static fn (Application $app): EloquentIdentityProvider => new EloquentIdentityProvider($app->make(Hasher::class), IntegrationIdentity::class));

        config()->set('auth.providers.identities.driver', 'evented');

        Auth::forgetGuards();

        $listening = true;
        $between   = null;

        IntegrationIdentity::updated(function (IntegrationIdentity $saved) use (&$listening, &$between): void {

            if (!$listening) {
                return;
            }

            $listening = false;

            IntegrationIdentity::query()->whereKey($saved->getKey())->firstOrFail()->forceFill(['password' => app(Hasher::class)->make('a new password')])->save();

            $between = $this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'a new password'], self::requestContext())->session;

            $saved->forceFill(['password' => app(Hasher::class)->make(self::PASSWORD)])->save();
        });

        $after = $this->signIn();

        self::assertInstanceOf(SignedInSession::class, $between);
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) $identity->fresh()?->getAuthPassword()));

        $this->assertSessionEnded($before);
        $this->assertSessionEnded($between);

        $this->bearer($after->tokens->accessToken->reveal())->assertOk();
    }

    /**
     * A reset through the password broker ends the session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordResetEndsTheSession(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn();

        DB::table('integration_identities')->update(['password' => app(Hasher::class)->make('a reset password')]);

        Event::dispatch(new PasswordReset($identity));

        $this->assertSessionEnded($session);
    }

    /**
     * Laravel's rehash keeps the session for an observer registered by
     * `#[ObservedBy]`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLaravelsRehashKeepsTheSessionForAnObserverRegisteredByAttribute(): void
    {
        $this->seedIdentity();

        config()->set('auth.providers.identities.model', AttributeObservedIdentity::class);
        config()->set('auth.providers.users', ['driver' => 'eloquent', 'model' => AttributeObservedIdentity::class]);
        config()->set('auth.guards.web', ['driver' => 'session', 'provider' => 'users']);
        config()->set('session.driver', 'array');

        Auth::forgetGuards();

        $session  = $this->signIn();
        $outdated = (new BcryptHasher(['rounds' => 5]))->make(self::PASSWORD);

        DB::table('integration_identities')->update(['password' => $outdated]);

        AttributeObservedIdentity::flushEventListeners();
        AttributeObservedIdentity::clearBootedModels();

        $guard = Auth::guard('web');

        self::assertInstanceOf(SessionGuard::class, $guard);
        self::assertTrue($guard->attempt(self::credentials()));
        self::assertNotSame($outdated, DB::table('integration_identities')->value('password'));

        $this->bearer($session->tokens->accessToken->reveal())->assertOk();

        AttributeObservedIdentity::query()->firstOrFail()->forceFill(['password' => app(Hasher::class)->make('a new password')])->save();

        $this->assertSessionEnded($session);
    }

    /**
     * A deactivated identity's session stays ended after reactivation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeactivationEndsTheSessionBeyondAReactivation(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn();

        $identity->forceFill(['is_active' => false])->save();
        $identity->forceFill(['is_active' => true])->save();

        $this->assertSessionEnded($session);
    }

    /**
     * Register the guards.
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
     * Sign the seeded identity in, a minute before the change that follows.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(): SignedInSession
    {
        $session = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        $this->bearer($session->tokens->accessToken->reveal())->assertOk();
        $this->moveClocksTo(CarbonImmutable::now()->addMinute());

        return $session;
    }

    /**
     * Assert the session's access and refresh tokens no longer work.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return void
     */
    private function assertSessionEnded(SignedInSession $session): void
    {
        $this->bearer($session->tokens->accessToken->reveal())->assertUnauthorized();

        $this->postJson('/refresh', ['refresh_token' => $session->tokens->refreshToken?->reveal()])->assertOk()->assertExactJson(['refreshed' => false]);
    }

    /**
     * Send a request with the bearer token to the protected route.
     *
     * @param  string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(#[\SensitiveParameter] string $token): TestResponse
    {
        Auth::forgetGuards();

        return $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/me');
    }

    /**
     * Freeze every clock at the time.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    private function moveClocksTo(CarbonImmutable $time): void
    {
        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }
}
