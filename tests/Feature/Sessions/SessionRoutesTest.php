<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\QueryException;
use Illuminate\Foundation\Application;
use Illuminate\Http\Exceptions\ThrottleRequestsException;
use Illuminate\Http\JsonResponse;
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
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\PendingSession;
use SineMacula\Laravel\Authentication\Sessions\SessionEstablishment;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Feature tests of the documented sign-in and further-factor routes, registered
 * as an application would and driven over HTTP: `Auth::sessions('api')` signs
 * in, a pending session is looked up, discarded on a wrong code and satisfied
 * on the right one, and the access tokens the routes return authenticate
 * through `auth:api`, against the shipped application policy and attempt
 * limiter.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(SessionEstablishment::class)]
#[CoversClass(AuthManager::class)]
final class SessionRoutesTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string The further factor the test verifier accepts. */
    private const string CODE = '246810';

    /**
     * Create the tables and register the documented routes, with a verifier
     * that accepts one code, and a route behind `auth:api`.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        Route::post('/sign-in', self::signIn(...));
        Route::post('/factor', self::satisfyWithAFactor(...));

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

        $response = $this->send('/sign-in', self::credentials() + ['client_name' => 'Phone'])->assertOk();
        $tokens   = $response->json();

        self::assertTrue($response->baseResponse->headers->hasCacheControlDirective('no-store'));
        self::assertSame('no-cache', $response->baseResponse->headers->get('Pragma'));
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
            'factor without a credential'  => ['/factor', ['code' => self::CODE], 'pending_credential'],
            'factor with a list of codes'  => ['/factor', ['pending_credential' => 'x.y', 'code' => [self::CODE]], 'code'],
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
     * A sign-in that needs a further factor answers with its pending session's
     * id, what it waits on and its pending credential, in the body, which
     * authenticates nothing; a wrong code discards the session, so the right
     * code on it then satisfies nothing; a new sign-in with the right code
     * activates, keeping its id, and its access token authenticates; the
     * consumed credential is spent.
     *
     * @return void
     */
    public function testAFurtherFactorIsSatisfiedOrDiscardedThroughTheRoutes(): void
    {
        $this->seedIdentity();

        $factors = \Mockery::mock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requirementFor')->andReturn(new Requirement(new RequirementPart));

        app()->instance(AdditionalFactorPolicy::class, $factors);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $first = $this->send('/sign-in', self::credentials())->assertOk()->assertJsonPath('status', 'pending')->assertJsonPath('requires', ['mfa']);

        $guessed = $first->json('pending_credential');
        $id      = $first->json('id');

        self::assertIsString($guessed);
        self::assertIsString($id);
        self::assertStringStartsWith($id . '.', $guessed);

        $this->bearer($guessed)->assertUnauthorized();
        $this->send('/factor', ['pending_credential' => $guessed, 'code' => '000000'])->assertUnauthorized();

        self::assertSame('signed_out', Session::query()->sole()->getRevokedReason());

        $this->send('/factor', ['pending_credential' => $guessed, 'code' => self::CODE])->assertUnauthorized();

        $second  = $this->send('/sign-in', self::credentials())->assertOk();
        $pending = $second->json('pending_credential');

        self::assertIsString($pending);

        $active = $this->send('/factor', ['pending_credential' => $pending, 'code' => self::CODE])->assertOk();
        $access = $active->json('access_token');

        self::assertIsString($access);
        self::assertSame($second->json('id'), $active->json('id'));

        $this->bearer($access)->assertOk()->assertExactJson(['email' => 'ada@example.test']);
        $this->send('/factor', ['pending_credential' => $pending, 'code' => self::CODE])->assertUnauthorized();
    }

    /**
     * A further factor satisfied while its slots cannot be given back still
     * answers with a token pair whose access token authenticates: the counters'
     * error is reported, not thrown, since the session already stands, and the
     * slots stay counted.
     *
     * @return void
     */
    public function testAnActivationWhoseSlotsCannotBeGivenBackStillAnswersWithItsTokens(): void
    {
        $this->seedIdentity();

        $factors = \Mockery::mock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requirementFor')->andReturn(new Requirement(new RequirementPart));

        app()->instance(AdditionalFactorPolicy::class, $factors);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $pending = $this->send('/sign-in', self::credentials())->assertOk()->json('pending_credential');

        self::assertIsString($pending);

        $exceptions = Exceptions::fake([QueryException::class]);

        Schema::rename('rate_limits', 'unreachable_rate_limits');

        try {
            $access = $this->send('/factor', ['pending_credential' => $pending, 'code' => self::CODE])->assertOk()->json('access_token');
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
     * The documented sign-in route: validate, sign in through the session
     * service, answer a throttled sign-in 429 with the wait and any other
     * failure 401, and hand out the pending session's id, what it waits on and
     * its pending credential, in the body, or the token pair, never stored.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Http\Exceptions\ThrottleRequestsException
     */
    private static function signIn(Request $request): JsonResponse
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

        if ($result->pending !== null) {
            return SecretResponse::json(self::pendingBody($result->pending, $result->credential));
        }

        return SecretResponse::json([
            'access_token'  => $result->session?->tokens->accessToken,
            'refresh_token' => $result->session?->tokens->refreshToken,
        ]);
    }

    /**
     * The body a pending sign-in answers with: the session's id, what it waits
     * on, and its pending credential.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\PendingSession  $pending
     * @param  ?\SineMacula\Laravel\Authentication\Secrets\Secret  $credential
     * @return array<string, mixed>
     */
    private static function pendingBody(PendingSession $pending, ?Secret $credential): array
    {
        return [
            'status'             => 'pending',
            'id'                 => $pending->id,
            'requires'           => array_map(static fn (PendingRequirement $requirement): string => $requirement->value, $pending->requires),
            'pending_credential' => $credential,
        ];
    }

    /**
     * The documented further-factor route, as an adapter for the factor package
     * runs it: validate, check the pending credential allows verifying a
     * factor, verify the code for the session's identity, discard the session
     * on a wrong code, and on the right one hand the verification's proof,
     * bound to the session, to `satisfy()`, and answer with the new access
     * token, never stored.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function satisfyWithAFactor(Request $request): JsonResponse
    {
        ['pending_credential' => $credential, 'code' => $code] = $request->validate([ // @phpstan-ignore staticMethod.dynamicCall
            'pending_credential' => ['required', 'string'],
            'code'               => ['required', 'string'],
        ]);

        $verify   = static fn (Identity $identity, string $code): bool => $code === self::CODE;
        $sessions = Auth::sessions('api');
        $pending  = $sessions->pending($credential, PendingAction::VERIFY);

        if ($pending === null) {
            abort(401);
        }

        if (!$verify($pending->identity, $code)) {

            $sessions->discard($credential);

            abort(401);
        }

        $proof = new ProofResult(
            ProofKind::ADDITIONAL_FACTOR,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP),
            null,
            new ObservedProperties,
            new Evaluation(true, true),
            ['otp'],
            CarbonImmutable::now(),
            new ProofBinding($pending->identity, 'api', $pending->id, Purpose::SIGN_IN),
        );

        $result = $sessions->satisfy($credential, $proof, self::requestClient());

        abort_if(!$result->isSignedIn(), 401);

        return SecretResponse::json(['id' => $result->session?->record->getSessionIdentifier(), 'access_token' => $result->session?->tokens->accessToken]);
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
