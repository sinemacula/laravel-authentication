<?php

declare(strict_types = 1);

namespace Tests\Integration\Http;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Callers\CallerCredentials;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
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
use SineMacula\Laravel\Authentication\Sessions\PendingCredential;
use SineMacula\Laravel\Authentication\Sessions\SessionPreconditions;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * End-to-end tests of the documented pending-session routes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingCredential::class)]
#[CoversClass(SessionPreconditions::class)]
#[CoversClass(SessionService::class)]
#[CoversClass(CallerCredentials::class)]
final class PendingCredentialIntegrationTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string The body application whose sign-in waits on a further factor. */
    private const string FACTOR = 'api';

    /** @var string The body application whose sign-in waits on the choice of a membership. */
    private const string MEMBERS = 'members';

    /** @var string The address the routes' requests come from. */
    private const string ROUTE_IP = '192.0.2.61';

    /** @var string The id of the pending session the routes act on. */
    private string $pendingId = '';

    /**
     * Create the tables and register the pending-session routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        Route::post('/factor', fn (Request $request): JsonResponse => $this->factorRoute($request));
        Route::post('/choose', static fn (Request $request): JsonResponse => self::chooseRoute($request));
        Route::post('/caller/choose', static fn (Request $request): JsonResponse => self::callerChooseRoute($request))
            ->middleware('authentication.pending:choose_principal,' . self::MEMBERS);
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
     * Rows of `[route, credential sent, failures reported, status, session
     * status after]`.
     *
     * @return iterable<string, array{0: string, 1: string, 2: int, 3: int, 4: string}>
     */
    public static function provideCredentials(): iterable
    {
        foreach (['/factor', '/choose', '/caller/choose'] as $route) {
            yield "{$route}, none" => [$route, 'none', 0, 401, 'pending'];
            yield "{$route}, malformed" => [$route, 'malformed', 1, 401, 'pending'];
            yield "{$route}, unknown" => [$route, 'unknown', 1, 401, 'pending'];
            yield "{$route}, live" => [$route, 'live', 0, 200, 'active'];
        }
    }

    /**
     * Each route reports a bad credential once and activates a live one.
     *
     * @param  string  $route
     * @param  string  $sent
     * @param  int  $failures
     * @param  int  $status
     * @param  string  $session
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideCredentials')]
    public function testEachRouteAnswersEachPendingCredential(string $route, string $sent, int $failures, int $status, string $session): void
    {
        $started = $route === '/factor' ? $this->startFactor() : $this->startChoice();
        $live    = $started->credential;

        $id = $started->pending?->id;

        self::assertInstanceOf(Secret::class, $live);
        self::assertIsString($id);

        $this->pendingId = $id;

        $body = match ($sent) {
            'none'      => [],
            'malformed' => ['pending_credential' => ['not', 'a', 'string']],
            'unknown'   => ['pending_credential' => $this->pendingId . '.' . str_repeat('A', 43)],
            default     => ['pending_credential' => $live->reveal()],
        };

        $this->recordEvents([AuthenticationFailed::class]);

        $this->send($route, $body)->assertStatus($status);

        self::assertCount($failures, $this->recorded);
        self::assertSame($session, DB::table('authentication_sessions')->where('id', $this->pendingId)->value('status'));

        if ($failures === 0) {
            return;
        }

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([AuthenticationFlow::SIGN_IN, FailureReason::PENDING_INVALID], [$failure->flow, $failure->reason]);
        self::assertSame([self::ROUTE_IP, 'Route/1.0'], [$failure->context->client->ip, $failure->context->client->userAgent]);
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
     * The documented choice route.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function chooseRoute(Request $request): JsonResponse
    {
        $credential = PendingCredential::extract($request);

        abort_if($credential === null, 401);

        return self::answer(Auth::sessions(self::MEMBERS)->choose($credential, self::membershipNamed($request), ClientContext::fromRequest($request)));
    }

    /**
     * A choice route that reads the request's caller first.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private static function callerChooseRoute(Request $request): JsonResponse
    {
        abort_if(Auth::caller() === null, 401);

        $credential = PendingCredential::extract($request);

        self::assertInstanceOf(Secret::class, $credential);

        return self::answer(Auth::sessions(self::MEMBERS)->choose($credential, self::membershipNamed($request), ClientContext::fromRequest($request)));
    }

    /**
     * The membership the request names to choose.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Tests\Integration\Fixtures\ActivatableTenantMembership
     */
    private static function membershipNamed(Request $request): ActivatableTenantMembership
    {
        return ActivatableTenantMembership::query()->findOrFail($request->header('X-Membership'));
    }

    /**
     * The id of the session an activation signed in, or 401 for anything else.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @return \Illuminate\Http\JsonResponse
     */
    private static function answer(SignInResult $result): JsonResponse
    {
        abort_unless($result->isSignedIn(), 401);

        return new JsonResponse(['id' => $result->session?->record->getSessionIdentifier()]);
    }

    /**
     * The documented further-factor route.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Throwable
     */
    private function factorRoute(Request $request): JsonResponse
    {
        $credential = PendingCredential::extract($request);

        abort_if($credential === null, 401);

        $proof = new ProofResult(
            ProofKind::ADDITIONAL_FACTOR,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP),
            null,
            new ObservedProperties,
            new Evaluation(true, true),
            ['otp'],
            CarbonImmutable::now(),
            new ProofBinding(IntegrationIdentity::query()->sole(), self::FACTOR, $this->pendingId, Purpose::SIGN_IN),
        );

        return self::answer(Auth::sessions(self::FACTOR)->satisfy($credential, $proof, ClientContext::fromRequest($request)));
    }

    /**
     * Sign an identity in on the guard whose sign-in waits on a further factor.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function startFactor(): SignInResult
    {
        $this->seedIdentity();

        $factors = \Mockery::mock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requirementFor')->andReturn(new Requirement(new RequirementPart));

        app()->instance(AdditionalFactorPolicy::class, $factors);
        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        return $this->sessions(self::FACTOR)->signIn('password', self::credentials(), self::requestContext());
    }

    /**
     * Sign a member of two tenants in, its sign-in waiting on the choice of a
     * membership, and name the first for the routes to choose.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function startChoice(): SignInResult
    {
        [$member, $membership] = $this->seedMember();

        $other = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);

        ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);

        $this->withHeader('X-Membership', (string) IdentifierCoercion::stringify($membership->getKey()));

        return $this->sessions(self::MEMBERS)->signIn('password', self::credentials('member@example.test'), self::requestContext());
    }

    /**
     * Post the body to the route as a JSON request from the route's client.
     *
     * @param  string  $route
     * @param  array<string, mixed>  $body
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function send(string $route, array $body): TestResponse
    {
        Auth::forgetGuards();

        return $this->withServerVariables(['REMOTE_ADDR' => self::ROUTE_IP])->withHeader('User-Agent', 'Route/1.0')->postJson($route, $body);
    }
}
