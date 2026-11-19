<?php

declare(strict_types = 1);

namespace Tests\Integration\Http;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;
use SineMacula\Laravel\Authentication\Sessions\RefreshResult;
use SineMacula\Laravel\Authentication\Sessions\SessionActivation;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionStepUp;
use SineMacula\Laravel\Authentication\Sessions\SessionSwitch;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Sessions\SwitchResult;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * End-to-end test of a sign-in that waits on a further factor, followed over
 * HTTP through refresh, switch, step-up and sign-out.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(SessionActivation::class)]
#[CoversClass(JwtTokenService::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(SessionSwitch::class)]
#[CoversClass(SessionStepUp::class)]
final class SignInJourneyTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessions;

    /** @var string The body application over tenant members. */
    private const string GUARD = 'members';

    /**
     * Freeze the clocks, create the tables, require a further factor at sign-in
     * and register the routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clockAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));
        $this->createSessionTables();

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        Route::post('/sign-in', self::signInRoute(...));
        Route::post('/factor', self::factorRoute(...));
        Route::post('/refresh', static fn (Request $request): JsonResponse => self::tokensOrRefusal(
            Auth::sessions(self::GUARD)->refresh(self::presented($request), self::requestClient()),
        ));
        Route::post('/switch', static fn (Request $request): JsonResponse => self::tokensOrRefusal(Auth::sessions(self::GUARD)->switchTo(
            self::presented($request),
            SwitchTarget::principal(ActivatableTenantMembership::query()->findOrFail($request->integer('membership'))),
            self::requestClient(),
        )));

        Route::middleware('auth:' . self::GUARD)->group(static function (): void {
            Route::get('/me', static fn (): array => ['principal' => Auth::principal()?->getPrincipalIdentifier()]);
            Route::post('/step-up', self::stepUpRoute(...));
            Route::post('/logout', static fn (): array => ['signed_out' => Auth::sessions(self::GUARD)->signOut()]);
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
     * A session activated by a further factor keeps the factor through refresh,
     * switch and step-up, and signing out ends every credential it held.
     *
     * @return void
     */
    public function testAnActivatedSessionKeepsItsFactorUntilItSignsOut(): void
    {
        [$member, $first] = $this->seedMember();

        $other  = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $second = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);
        $signIn = CarbonImmutable::now();

        $pending = $this->postJson('/sign-in')->assertOk()->assertJsonPath('status', 'pending')->assertJsonPath('requires', ['mfa'])->json('pending_credential');

        self::assertIsString($pending);

        $factoredAt = $signIn->addSeconds(30);

        $this->clockAt($factoredAt);

        $activated = $this->postJson('/factor', ['pending_credential' => $pending])->assertOk();

        $this->assertAuthenticates($activated, $first, $factoredAt, ['pwd', 'otp', 'mfa']);

        $this->clockAt($signIn->addMinute());

        $refreshed = $this->send('/refresh', $activated)->assertOk();

        $this->assertAuthenticates($refreshed, $first, $factoredAt, ['pwd', 'otp', 'mfa']);

        $this->clockAt($signIn->addMinutes(2));

        $switched = $this->send('/switch', $refreshed, ['membership' => $second->getKey()])->assertOk();

        $this->assertAuthenticates($switched, $second, $factoredAt, ['pwd', 'otp', 'mfa']);

        $steppedUpAt = $signIn->addMinutes(3);

        $this->clockAt($steppedUpAt);

        $steppedUp = $this->bearer('POST', '/step-up', $switched)->assertOk();

        $this->assertAuthenticates($steppedUp, $second, $steppedUpAt, ['pwd', 'otp', 'hwk', 'mfa']);

        $this->clockAt($signIn->addMinutes(4));

        $latest = $this->send('/refresh', $switched)->assertOk();

        $this->assertAuthenticates($latest, $second, $steppedUpAt, ['pwd', 'otp', 'hwk', 'mfa']);

        $this->bearer('POST', '/logout', $latest)->assertOk()->assertExactJson(['signed_out' => true]);

        foreach ([$activated, $refreshed, $switched, $steppedUp, $latest] as $held) {
            $this->bearer('GET', '/me', $held)->assertUnauthorized();
        }

        foreach ([$activated, $refreshed, $switched, $latest] as $held) {
            $this->send('/refresh', $held)->assertUnauthorized()->assertExactJson(['reason' => 'session_revoked']);
        }

        $this->postJson('/factor', ['pending_credential' => $pending])->assertUnauthorized()->assertExactJson(['reason' => 'pending_invalid']);
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
     * Sign the member in as its default membership and answer with the pending
     * credential the further factor waits on.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function signInRoute(Request $request): JsonResponse
    {
        $member  = ActivatableTenantMember::query()->where('email', 'member@example.test')->firstOrFail();
        $context = SignInContext::fromRequest($request, principal: $member->resolveDefaultPrincipal());
        $result  = Auth::sessions(self::GUARD)->signIn('password', self::credentials('member@example.test'), $context);

        return SecretResponse::json(['status' => $result->status->value, 'requires' => $result->pending?->requires, 'pending_credential' => $result->credential]);
    }

    /**
     * Satisfy the further factor with a one-time code its adapter verified.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function factorRoute(Request $request): JsonResponse
    {
        $credential = $request->string('pending_credential')->toString();
        $sessions   = Auth::sessions(self::GUARD);
        $pending    = $sessions->pending($credential);
        $member     = ActivatableTenantMember::query()->where('email', 'member@example.test')->firstOrFail();
        $proof      = self::adapterProof($member, self::GUARD, $pending?->id, Purpose::SIGN_IN);

        return self::tokensOrRefusal($sessions->satisfy($credential, $proof, self::requestClient()));
    }

    /**
     * Step the bearer's session up with a hardware key its adapter verified.
     *
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function stepUpRoute(): JsonResponse
    {
        $member = Auth::identity();

        assert($member instanceof ActivatableTenantMember);

        $result = Auth::sessions(self::GUARD)->stepUp(self::adapterProof($member, self::GUARD, Auth::session()?->getSessionIdentifier(), methods: ['hwk']), self::requestClient());

        return SecretResponse::json(['access_token' => $result->accessToken]);
    }

    /**
     * Answer with the result's token pair, or with why it was refused.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\RefreshResult|\SineMacula\Laravel\Authentication\Sessions\SignInResult|\SineMacula\Laravel\Authentication\Sessions\SwitchResult|null  $result
     * @return \Illuminate\Http\JsonResponse
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private static function tokensOrRefusal(RefreshResult|SignInResult|SwitchResult|null $result): JsonResponse
    {
        $tokens = $result?->session?->tokens;

        if ($tokens === null) {
            return new JsonResponse(['reason' => $result?->reason?->value], 401);
        }

        return SecretResponse::json(['access_token' => $tokens->accessToken, 'refresh_token' => $tokens->refreshToken]);
    }

    /**
     * The refresh token the request's body presents.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Http\PresentedRefreshToken
     */
    private static function presented(Request $request): PresentedRefreshToken
    {
        return PresentedRefreshToken::fromBody($request->string('refresh_token')->toString());
    }

    /**
     * Assert the response's access token authenticates as the principal, and
     * carries the authentication time and methods.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @param  \Tests\Integration\Fixtures\ActivatableTenantMembership  $principal
     * @param  \Carbon\CarbonImmutable  $authenticatedAt
     * @param  list<string>  $methods
     * @return void
     */
    private function assertAuthenticates(TestResponse $response, ActivatableTenantMembership $principal, CarbonImmutable $authenticatedAt, array $methods): void
    {
        $claims = Auth::manager()->jwt(self::GUARD)->parse(self::accessTokenOf($response), TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame([$authenticatedAt->getTimestamp(), $methods], [$claims['auth_time'] ?? null, $claims['amr'] ?? null]);

        $this->bearer('GET', '/me', $response)->assertOk()->assertExactJson(['principal' => $principal->id]);
    }

    /**
     * Post the refresh token the earlier response answered with.
     *
     * @param  string  $uri
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $tokens
     * @param  array<string, mixed>  $input
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function send(string $uri, TestResponse $tokens, array $input = []): TestResponse
    {
        Auth::forgetGuards();

        return $this->postJson($uri, ['refresh_token' => $tokens->json('refresh_token'), ...$input]);
    }

    /**
     * Send a request with the access token the earlier response answered with.
     *
     * @param  string  $method
     * @param  string  $uri
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $tokens
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(string $method, string $uri, TestResponse $tokens): TestResponse
    {
        Auth::forgetGuards();

        return $this->withHeaders(['Authorization' => 'Bearer ' . self::accessTokenOf($tokens)])->json($method, $uri);
    }

    /**
     * The access token the response answered with.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @return string
     */
    private static function accessTokenOf(TestResponse $response): string
    {
        $token = $response->json('access_token');

        self::assertIsString($token);

        return $token;
    }

    /**
     * Freeze every clock at the time.
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @return void
     */
    private function clockAt(CarbonImmutable $at): void
    {
        Carbon::setTestNow($at);
        CarbonImmutable::setTestNow($at);

        JWT::$timestamp = $at->getTimestamp();
    }
}
