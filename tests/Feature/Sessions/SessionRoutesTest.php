<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Exceptions;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Feature tests of the README's sign-in and further-factor routes, registered
 * as an application would and driven over HTTP: `Auth::sessions('api')` signs
 * in, a pending sign-in is looked up, discarded on a wrong code and completed
 * on the right one, and the access tokens the routes return authenticate
 * through `auth:api`, against the shipped audience policy and attempt limiter.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(AuthManager::class)]
final class SessionRoutesTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string The further factor the test verifier accepts. */
    private const string CODE = '246810';

    /**
     * Create the tables and register the README's routes, with a verifier that
     * accepts one code, and a route behind `auth:api`.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        Route::post('/sign-in', self::signIn(...));
        Route::post('/factor', self::completeWithAFactor(...));

        Route::middleware('auth:api')->get('/me', static function (): array {

            $identity = Auth::identity();

            return ['email' => $identity instanceof IntegrationIdentity ? $identity->email : null];
        });
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * Signing in through the route returns a token pair, and the access token
     * authenticates through `auth:api` as the identity that signed in.
     *
     * @return void
     */
    public function testSigningInReturnsTokensThatAuthenticateThroughTheMiddleware(): void
    {
        $this->seedIdentity();

        $tokens = $this->send('/sign-in', self::credentials() + ['client_name' => 'Phone'])->assertOk()->json();

        self::assertIsArray($tokens);
        self::assertIsString($tokens['access_token']);
        self::assertIsString($tokens['refresh_token']);

        $this->bearer($tokens['access_token'])->assertOk()->assertExactJson(['email' => 'ada@example.test']);
        $this->bearer($tokens['refresh_token'])->assertUnauthorized();
    }

    /**
     * Rows of `[path, body, field]`: requests whose validation fails, with the
     * field it fails on.
     *
     * @return iterable<string, array{0: string, 1: array<string, mixed>, 2: string}>
     */
    public static function provideMalformedRequests(): iterable
    {
        yield from [
            'sign-in without a password'   => ['/sign-in', ['email' => 'ada@example.test'], 'password'],
            'sign-in with a list of email' => ['/sign-in', ['email' => ['ada@example.test'], 'password' => self::PASSWORD], 'email'],
            'sign-in with a list name'     => ['/sign-in', ['client_name' => ['Phone']] + self::credentials(), 'client_name'],
            'factor without a token'       => ['/factor', ['code' => self::CODE], 'pending_token'],
            'factor with a list of codes'  => ['/factor', ['pending_token' => 'x.y', 'code' => [self::CODE]], 'code'],
        ];
    }

    /**
     * Malformed input is answered with a 422 by the route's validation, never a
     * server error, and signs nobody in.
     *
     * @param  string  $path
     * @param  array<string, mixed>  $body
     * @param  string  $field
     * @return void
     */
    #[DataProvider('provideMalformedRequests')]
    public function testMalformedInputIsAnswered422(string $path, array $body, string $field): void
    {
        $this->seedIdentity();

        $this->send($path, $body)->assertUnprocessable()->assertJsonValidationErrors([$field]);
    }

    /**
     * A wrong password is answered with a 401; once the identifier has used up
     * its attempts, the route answers 429 with the wait in `Retry-After`, even
     * for the right password.
     *
     * @return void
     */
    public function testAThrottledSignInIsAnswered429WithTheWait(): void
    {
        $this->seedIdentity();

        for ($attempt = 0; $attempt < 5; $attempt++) {
            $this->send('/sign-in', ['email' => 'ada@example.test', 'password' => 'wrong'])->assertUnauthorized();
        }

        $throttled = $this->send('/sign-in', self::credentials())->assertTooManyRequests();
        $wait      = $throttled->headers->get('Retry-After');

        self::assertIsString($wait);
        self::assertGreaterThanOrEqual(1, (int) $wait);
        self::assertLessThanOrEqual(300, (int) $wait);
    }

    /**
     * A sign-in that needs a further factor returns a pending token, which
     * authenticates nothing; a wrong code discards it, so the right code on it
     * then completes nothing; a new sign-in with the right code completes, and
     * its access token authenticates.
     *
     * @return void
     */
    public function testAFurtherFactorIsCompletedOrDiscardedThroughTheRoutes(): void
    {
        $this->seedIdentity();

        $factors = \Mockery::mock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requiresAdditionalFactor')->andReturnTrue();

        app()->instance(AdditionalFactorPolicy::class, $factors);

        $guessed = $this->send('/sign-in', self::credentials())->assertOk()->json('pending_token');

        self::assertIsString($guessed);

        $this->bearer($guessed)->assertUnauthorized();
        $this->send('/factor', ['pending_token' => $guessed, 'code' => '000000'])->assertUnauthorized();

        self::assertSame(0, PendingSignIn::query()->count());

        $this->send('/factor', ['pending_token' => $guessed, 'code' => self::CODE])->assertUnauthorized();

        $pending = $this->send('/sign-in', self::credentials())->assertOk()->json('pending_token');

        self::assertIsString($pending);

        $access = $this->send('/factor', ['pending_token' => $pending, 'code' => self::CODE])->assertOk()->json('access_token');

        self::assertIsString($access);

        $this->bearer($access)->assertOk()->assertExactJson(['email' => 'ada@example.test']);
        $this->send('/factor', ['pending_token' => $pending, 'code' => self::CODE])->assertUnauthorized();
    }

    /**
     * A further factor completed while its slots cannot be given back still
     * answers with a token pair whose access token authenticates: the counters'
     * error is reported, not thrown, since the session already stands, and the
     * slots stay counted.
     *
     * @return void
     */
    public function testACompletionWhoseSlotsCannotBeGivenBackStillAnswersWithItsTokens(): void
    {
        $this->seedIdentity();

        $factors = \Mockery::mock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requiresAdditionalFactor')->andReturnTrue();

        app()->instance(AdditionalFactorPolicy::class, $factors);

        $pending = $this->send('/sign-in', self::credentials())->assertOk()->json('pending_token');

        self::assertIsString($pending);

        $exceptions = Exceptions::fake([QueryException::class]);

        Schema::rename('rate_limits', 'unreachable_rate_limits');

        try {
            $access = $this->send('/factor', ['pending_token' => $pending, 'code' => self::CODE])->assertOk()->json('access_token');
        } finally {
            Schema::rename('unreachable_rate_limits', 'rate_limits');
        }

        self::assertIsString($access);
        self::assertCount(1, $exceptions->reported());
        self::assertSame(3, DB::table('rate_limits')->count());
        self::assertSame(3, DB::table('rate_limits')->where('hits', 1)->count());

        $this->bearer($access)->assertOk()->assertExactJson(['email' => 'ada@example.test']);
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
     * The README's sign-in route: validate, sign in through the session
     * service, answer a throttled sign-in 429 with the wait and any other
     * failure 401, and hand out the pending token or the token pair.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array<string, ?string>
     *
     * @throws \Illuminate\Http\Exceptions\ThrottleRequestsException
     */
    private static function signIn(Request $request): array
    {
        $input = $request->validate([ // @phpstan-ignore staticMethod.dynamicCall
            'email'         => ['required', 'string'],
            'password'      => ['required', 'string'],
            'client_name'   => ['nullable', 'string'],
            'platform'      => ['nullable', 'string'],
            'refresh_token' => ['nullable', 'string'],
        ]);

        $result = Auth::sessions('api')->signIn(
            'password',
            ['email' => $input['email'], 'password' => $input['password']],
            SignInContext::fromRequest(
                $request,
                clientName: $input['client_name']     ?? null,
                platform: $input['platform']          ?? null,
                refreshToken: $input['refresh_token'] ?? null,
            ),
        );

        if ($result->isFailed()) {

            if ($result->reason === FailureReason::RATE_LIMITED) {
                throw new ThrottleRequestsException('Too Many Attempts.', null, ['Retry-After' => $result->retryAfter]);
            }

            abort(401);
        }

        if ($result->requiresFactor()) {
            return ['pending_token' => $result->pending?->token];
        }

        return [
            'access_token'  => $result->session?->tokens->accessToken,
            'refresh_token' => $result->session?->tokens->refreshToken,
        ];
    }

    /**
     * The README's further-factor route: validate, look the pending sign-in up,
     * verify the code for its identity and principal, discard it on a wrong
     * code, and complete it on the right one.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array<string, ?string>
     *
     * @throws \Throwable
     */
    private static function completeWithAFactor(Request $request): array
    {
        ['pending_token' => $token, 'code' => $code] = $request->validate([ // @phpstan-ignore staticMethod.dynamicCall
            'pending_token' => ['required', 'string'],
            'code'          => ['required', 'string'],
        ]);

        $verify   = static fn (Identity $identity, Principal $principal, string $code): bool => $code === self::CODE;
        $sessions = Auth::sessions('api');
        $pending  = $sessions->pending($token);

        if ($pending === null) {
            abort(401);
        }

        if (!$verify($pending->identity, $pending->principal, $code)) {

            $sessions->discard($token);

            abort(401);
        }

        $result = $sessions->complete($token);

        abort_if($result->isFailed(), 401);

        return ['access_token' => $result->session?->tokens->accessToken];
    }

    /**
     * Post the body to the route as a JSON request from a client of its own.
     *
     * @param  string  $path
     * @param  array<string, mixed>  $body
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function send(string $path, array $body): TestResponse
    {
        Auth::forgetGuards();

        return $this->postJson($path, $body);
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
