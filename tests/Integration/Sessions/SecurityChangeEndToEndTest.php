<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\PasswordReset;
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
use SineMacula\Laravel\Authentication\Listeners\Concerns\RevokesOnceCommitted;
use SineMacula\Laravel\Authentication\Listeners\RevokeDevicesOnDeactivation;
use SineMacula\Laravel\Authentication\Listeners\RevokeDevicesOnPasswordChange;
use SineMacula\Laravel\Authentication\Listeners\RevokeDevicesOnPasswordReset;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\EloquentIdentityProvider;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * End-to-end tests of the optional security-change listeners against a real
 * database, as an application registers them: once the change commits, the
 * sessions it ends are refused at the `auth` middleware and can no longer be
 * refreshed, while a session started afterwards works.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevokeDevicesOnPasswordChange::class)]
#[CoversClass(RevokeDevicesOnPasswordReset::class)]
#[CoversClass(RevokeDevicesOnDeactivation::class)]
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

            return ['refreshed' => $guard->refresh($request->string('refresh_token')->toString()) !== null];
        });

        IntegrationIdentity::observe([RevokeDevicesOnPasswordChange::class, RevokeDevicesOnDeactivation::class]);

        Event::listen(PasswordReset::class, RevokeDevicesOnPasswordReset::class);
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
     * A new password saved in a transaction leaves the session working until
     * the transaction commits; then its access token is refused and its refresh
     * token refreshes nothing, while a sign-in with the new password works.
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

            $this->bearer($session->tokens->accessToken)->assertOk();
        });

        $this->assertSessionEnded($session);

        self::assertTrue($this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'a new password'])->isSignedIn());
    }

    /**
     * A sign-in through a user provider whose rehash of an outdated hash fires
     * model events, with a listener of the rehash's save that changes the
     * password through another instance, signs in with the new one, then saves
     * the sign-in password back through the instance the rehash saved: the
     * change back ends the session started between the two changes, as the
     * first change ended the one before, while the sign-in around them works.
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

            $between = $this->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => 'a new password'])->session;

            $saved->forceFill(['password' => app(Hasher::class)->make(self::PASSWORD)])->save();
        });

        $after = $this->signIn();

        self::assertInstanceOf(SignedInSession::class, $between);
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) $identity->fresh()?->getAuthPassword()));

        $this->assertSessionEnded($before);
        $this->assertSessionEnded($between);

        $this->bearer($after->tokens->accessToken)->assertOk();
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
     * A deactivated identity's session stays ended once the identity is active
     * again: the revocation outlasts the reactivation.
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
        $session = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        $this->bearer($session->tokens->accessToken)->assertOk();
        $this->moveClocksTo(CarbonImmutable::now()->addMinute());

        return $session;
    }

    /**
     * Assert the session's access token is refused at the `auth` middleware and
     * its refresh token refreshes nothing.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return void
     */
    private function assertSessionEnded(SignedInSession $session): void
    {
        $this->bearer($session->tokens->accessToken)->assertUnauthorized();

        $this->postJson('/refresh', ['refresh_token' => $session->tokens->refreshToken])->assertOk()->assertExactJson(['refreshed' => false]);
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
