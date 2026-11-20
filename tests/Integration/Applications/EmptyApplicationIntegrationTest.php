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
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Proofs\UndescribedFirstFactor;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\TestCase;

/**
 * Integration tests of an application that lists no method, the package
 * default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(GuardApplicationPolicy::class)]
final class EmptyApplicationIntegrationTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessions;

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

            $result = Auth::sessions('api')->refresh(PresentedRefreshToken::fromBody($request->string('refresh_token')->toString()), self::requestClient());

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
     * Without an `application` block every sign-in is refused as
     * `method_not_allowed` and nothing is written.
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
        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->sessions()->signIn('password', self::credentials(), self::requestContext())->reason);
        self::assertSame(0, $queries);
        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $this->sessions()->start(UndescribedFirstFactor::of($identity), null, 'password', self::requestContext())->reason);
        self::assertSame(0, DB::table('rate_limits')->count());
        self::assertSame(0, Session::query()->count());
    }

    /**
     * Emptying the list stops refreshes without revoking the session or its
     * access token.
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
     * Emptying the list leaves a waiting sign-in pending and unbound.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEmptiedListRefusesToCompleteAPendingSignIn(): void
    {
        $identity = $this->seedIdentity();

        config()->set('auth.guards.api.application', ['methods' => ['password']]);

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $result = $this->sessions()->signIn('password', self::credentials(), self::requestContext());

        self::assertNotNull($result->pending);
        self::assertNotNull($result->credential);

        config()->set('auth.guards.api.application', null);

        $credential = $result->credential->reveal();
        $proof      = self::adapterProof($identity, 'api', $result->pending->id, Purpose::SIGN_IN);
        $refused    = $this->sessions()->satisfy($credential, $proof, self::requestClient());

        self::assertSame(FailureReason::METHOD_NOT_ALLOWED, $refused->reason);
        self::assertNull($refused->session);
        self::assertFalse(Auth::guard('api')->hasUser());
        self::assertNull($this->sessions()->pending($credential));
        self::assertSame('pending', Session::query()->sole()->getAttribute('status'));
        self::assertSame(0, DB::table('authentication_proofs')->where('kind', ProofKind::ADDITIONAL_FACTOR->value)->count());

        config()->set('auth.guards.api.application', ['methods' => ['password']]);

        self::assertTrue($this->sessions()->satisfy($credential, $proof, self::requestClient())->isSignedIn());
        self::assertTrue(Auth::guard('api')->hasUser());
    }

    /**
     * Configure the guards and drop the `api` guard's `application` block.
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
        $session = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

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

        return $this->postJson('/refresh', ['refresh_token' => $session->tokens->refreshToken?->reveal()]);
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
