<?php

declare(strict_types = 1);

namespace Tests\Integration\Applications;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Applications\GuardApplicationPolicy;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * End-to-end tests of an application that lists no method, the package default,
 * against a real database on whichever engine the suite runs on: every sign-in
 * and refresh is refused as `method_not_allowed` without a write, an attempt
 * slot or a revocation, and access tokens already issued keep authenticating,
 * since the list decides admission, not revocation.
 *
 * The `api` guard has no `application` block, so it takes the shipped
 * `authentication.application`; a test that needs a session first lists the
 * password method on the guard, then removes the block again.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuardApplicationPolicy::class)]
final class EmptyApplicationIntegrationTest extends TestCase
{
    use InteractsWithSessions;

    /**
     * Freeze the clocks, create the tables, and add a protected route and a
     * refresh route.
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

        Route::middleware('auth:api')->get('/me', static fn (): array => ['identity' => Auth::identity()?->getAuthIdentifier()]);

        Route::post('/refresh', static function (Request $request): array {

            $result = Auth::sessions('api')->refresh($request->string('refresh_token')->toString());

            return ['refreshed' => $result->isRefreshed(), 'reason' => $result->reason?->value];
        });
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
     * Without an `application` block, `attempt()` and `signIn()` are refused as
     * `method_not_allowed` before anything is read, the identity, an attempt
     * slot or the password: no query runs. `start()`, which reloads the
     * identity it is given first, is refused the same way, and nothing is
     * counted or written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheShippedDefaultRefusesEverySignIn(): void
    {
        $identity = $this->seedIdentity();
        $queries  = 0;

        $this->recordEvents([AuthenticationFailed::class]);

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        self::assertFalse($this->freshGuard()->attempt(self::credentials()));
        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->sessions()->signIn('password', self::credentials())->reason);
        self::assertSame(0, $queries);
        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->sessions()->start($identity, null, 'password')->reason);
        self::assertSame(0, DB::table('rate_limits')->count());
        self::assertSame(0, Session::query()->count());
    }

    /**
     * A session started while the method was listed no longer refreshes once
     * the application lists nothing, through the route, and is not revoked; its
     * access token still authenticates until it expires; once the method is
     * listed again the same refresh token refreshes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEmptiedListStopsRefreshesWithoutRevokingAnything(): void
    {
        $this->seedIdentity();

        config()->set('auth.guards.api.application', ['methods' => ['password']]);

        $session = $this->signIn();

        config()->set('auth.guards.api.application', null);

        $this->refresh($session)->assertOk()->assertExactJson(['refreshed' => false, 'reason' => FailureReason::METHOD_NOT_ALLOWED->value]);

        self::assertNull($this->stored($session)->getRevokedAt());

        $this->bearer($session->tokens->accessToken->reveal())->assertOk()->assertExactJson(['identity' => $session->identity->getAuthIdentifier()]);

        config()->set('auth.guards.api.application', ['methods' => ['password']]);

        $this->refresh($session)->assertOk()->assertExactJson(['refreshed' => true, 'reason' => null]);
    }

    /**
     * Configure the guards and drop the `api` guard's `application` block, so
     * it lists what the package does: nothing.
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

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities']);
    }

    /**
     * Sign in with a password on the `api` guard and return the session.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(): SignedInSession
    {
        $session = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * The session as stored.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function stored(SignedInSession $session): Session
    {
        return Session::query()->whereKey($session->record->getSessionIdentifier())->firstOrFail();
    }

    /**
     * Send the session's refresh token to the refresh route.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function refresh(SignedInSession $session): TestResponse
    {
        Auth::forgetGuards();

        return $this->postJson('/refresh', ['refresh_token' => $session->tokens->refreshToken->reveal()]);
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
}
