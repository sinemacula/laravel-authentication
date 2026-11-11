<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Logout;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\Concerns\RefreshesSessions;
use SineMacula\Laravel\Authentication\Sessions\RefreshCredential;
use SineMacula\Laravel\Authentication\Sessions\SessionRefresh;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\MarksSharedLocks;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\TestCase;

/**
 * Feature tests of reading who the request's refresh credential would sign in
 * again, without rotating or binding.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshCredential::class)]
#[CoversClass(SessionRefresh::class)]
#[CoversClass(SessionService::class)]
#[CoversTrait(RefreshesSessions::class)]
final class RefreshCredentialTest extends TestCase
{
    use InteractsWithSessions, MarksSharedLocks;

    /** @var list<class-string> Every event a refresh or a sign-out could dispatch. */
    private const array EVENTS = [Attempting::class, Failed::class, AuthenticationFailed::class, SessionRevoked::class, Logout::class];

    /** @var string The cookie application, over the same identities as the body one. */
    private const string COOKIE = 'admin';

    /** @var string A rotation id the tests store the digest of, so they can issue tokens that carry it. */
    private const string KNOWN_ROTATION = 'known-rotation-id';

    /**
     * Freeze the clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveTo(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();
    }

    /**
     * Release the clock and drop the tables.
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
     * A body refresh token is its session owner's credential, without rotating
     * or binding anything.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenIsTheCredentialOfWhoARefreshWouldSignInAgain(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn();
        $before   = (array) DB::table('authentication_sessions')->sole();

        $this->recordEvents(self::EVENTS);

        $credential = $this->serving(body: ['refresh_token' => self::refreshOf($session)])->refreshCredential(self::servedToken(), self::requestClient());

        self::assertInstanceOf(RefreshCredential::class, $credential);
        self::assertIsModel($identity, $credential->identity);
        self::assertSame($identity->getPrincipalIdentifier(), $credential->principal->getPrincipalIdentifier());
        self::assertNull($credential->tenant);
        self::assertSame($session->record->getKey(), $credential->session->getKey());
        self::assertSame(RefreshTokenSource::BODY, $credential->source);
        self::assertSame([], $this->recordedClasses());
        self::assertEquals($before, (array) DB::table('authentication_sessions')->sole());
        self::assertTrue(Auth::guard('api')->guest());
    }

    /**
     * A member's header token carries its active tenant once that tenant's
     * policy is met.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAMembersCredentialCarriesItsActiveTenant(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->signedIn('members', 'member@example.test');
        $policy  = $this->tenantPolicy(new TenantRequirement('v2'));
        $before  = (array) DB::table('authentication_sessions')->sole();

        $credential = $this->serving(
            ['HTTP_X_REFRESH_TOKEN' => self::refreshOf($session)],
            guard: 'members',
        )->refreshCredential(self::servedToken('members'), self::requestClient());

        self::assertInstanceOf(RefreshCredential::class, $credential);
        self::assertIsModel($member, $credential->identity);
        self::assertSame($membership->getPrincipalIdentifier(), $credential->principal->getPrincipalIdentifier());
        self::assertSame($tenant->getTenantIdentifier(), $credential->tenant?->getTenantIdentifier());
        self::assertSame(RefreshTokenSource::HEADER, $credential->source);
        self::assertEquals($before, (array) DB::table('authentication_sessions')->sole());
        self::assertCount(1, $policy->asked);

        $asked = $policy->asked[0];

        self::assertSame('members', $asked->application);
        self::assertIsModel($member, $asked->identity);
        self::assertSame($membership->getPrincipalIdentifier(), $asked->principal->getPrincipalIdentifier());
        self::assertSame($tenant->getTenantIdentifier(), $asked->tenant->getTenantIdentifier());
        self::assertSame($session->record->getKey(), $asked->session?->getSessionIdentifier());
    }

    /**
     * A session its tenant policy would revoke on refresh is refused as
     * `sso_required` without being revoked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionTheNextRefreshWouldRevokeForItsTenantPolicyIsRefused(): void
    {
        $this->seedMember();

        $session = $this->signedIn('members', 'member@example.test');
        $before  = (array) DB::table('authentication_sessions')->sole();

        $this->tenantPolicy(new TenantRequirement('v2', connections: ['conn-a']));
        $this->recordEvents(self::EVENTS);

        self::assertSame(
            FailureReason::SSO_REQUIRED,
            $this->serving(body: ['refresh_token' => self::refreshOf($session)], guard: 'members')->refreshCredential(self::servedToken('members'), self::requestClient()),
        );
        self::assertSame([], $this->recordedClasses());
        self::assertEquals($before, (array) DB::table('authentication_sessions')->sole());
    }

    /**
     * A session its tenant policy would return to pending is refused as
     * `additional_factor_required`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionTheNextRefreshWouldReturnToPendingForItsTenantPolicyIsRefused(): void
    {
        $this->seedMember();

        $session = $this->signedIn('members', 'member@example.test');
        $before  = (array) DB::table('authentication_sessions')->sole();

        $this->tenantPolicy(new TenantRequirement('v2', new Requirement(new RequirementPart)));
        $this->recordEvents(self::EVENTS);

        self::assertSame(
            FailureReason::ADDITIONAL_FACTOR_REQUIRED,
            $this->serving(body: ['refresh_token' => self::refreshOf($session)], guard: 'members')->refreshCredential(self::servedToken('members'), self::requestClient()),
        );
        self::assertSame([], $this->recordedClasses());
        self::assertEquals($before, (array) DB::table('authentication_sessions')->sole());
    }

    /**
     * A credential is judged on plain reads of the session's proofs, without a
     * shared lock.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACredentialIsJudgedOnPlainReads(): void
    {
        $this->seedMember();

        $session = $this->signedIn('members', 'member@example.test');

        $this->tenantPolicy(new TenantRequirement('v2', new Requirement(new RequirementPart)));

        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        self::markSharedLocks();

        $service = $this->serving(body: ['refresh_token' => self::refreshOf($session)], guard: 'members');

        self::assertSame([false, false], self::proofReadLocks(static function () use ($service): void {
            self::assertSame(FailureReason::ADDITIONAL_FACTOR_REQUIRED, $service->refreshCredential(self::servedToken(), self::requestClient()));
        }));
    }

    /**
     * A request that carries no refresh token has no credential.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARequestWithoutATokenHasNoCredential(): void
    {
        $this->recordEvents(self::EVENTS);

        self::assertNull($this->serving()->refreshCredential(self::servedToken(), self::requestClient()));
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * Every refusal is returned as its reason for the caller to report.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEveryRefusalIsReturnedForTheCallerToReport(): void
    {
        $identity   = $this->seedIdentity();
        $other      = $this->seedIdentity('grace@example.test');
        $session    = $this->signedIn();
        $inactive   = $this->signedIn('api', 'grace@example.test');
        $unrecorded = $this->signedIn();

        DB::table('integration_identities')->where('id', $other->getKey())->update(['is_active' => false]);

        Session::query()->whereKey($unrecorded->record->getKey())->update([
            'principal_id' => IdentifierCoercion::stringify($other->getKey()),
            'refresh_key'  => RefreshTokenHasher::hash(self::KNOWN_ROTATION),
        ]);

        $unnamed = Auth::jwt('api')->issueRefreshToken($unrecorded->record, self::KNOWN_ROTATION)->reveal();
        $cases   = [
            'conflicting carriers' => [['HTTP_X_REFRESH_TOKEN' => 'one-token'], ['refresh_token' => 'another-token'], FailureReason::REFRESH_TOKEN_CONFLICT],
            'not a token'          => [[], ['refresh_token' => 'not-a-token'], FailureReason::TOKEN_INVALID],
            'an inactive owner'    => [[], ['refresh_token' => self::refreshOf($inactive)], FailureReason::IDENTITY_INACTIVE],
            'an unrecorded actor'  => [[], ['refresh_token' => $unnamed], FailureReason::SESSION_PRINCIPAL_MISMATCH],
        ];

        $this->recordEvents(self::EVENTS);

        foreach ($cases as $case => [$server, $body, $reason]) {
            self::assertSame($reason, $this->serving($server, $body)->refreshCredential(self::servedToken(), self::requestClient()), $case);
        }

        self::assertSame([], $this->recordedClasses());
        self::assertSame(0, Session::query()->whereNotNull('revoked_at')->count());

        $credential = $this->serving(body: ['refresh_token' => self::refreshOf($session)])->refreshCredential(self::servedToken(), self::requestClient());

        self::assertInstanceOf(RefreshCredential::class, $credential);
        self::assertIsModel($identity, $credential->identity);
    }

    /**
     * A cookie application's token is judged on the client given before any
     * query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACookieApplicationsTokenIsJudgedOnTheClientBeforeAnythingIsRead(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn(self::COOKIE);
        $token    = self::cookieTokenOf($session);

        $cookie     = self::presentedToken($token, RefreshTokenSource::COOKIE);
        $credential = self::sessionsOf($this->crossSiteGuard(self::COOKIE))->refreshCredential($cookie, self::sameSiteClient());

        self::assertInstanceOf(RefreshCredential::class, $credential);
        self::assertIsModel($identity, $credential->identity);
        self::assertSame(RefreshTokenSource::COOKIE, $credential->source);

        $service = $this->sessions(self::COOKIE);
        $twice   = self::presentedToken($token, RefreshTokenSource::COOKIE, [RefreshTokenSource::COOKIE, RefreshTokenSource::COOKIE]);
        $cases   = [
            'the cookie twice'    => [$twice, self::sameSiteClient(), FailureReason::REFRESH_TOKEN_CONFLICT],
            'a body token'        => [PresentedRefreshToken::fromBody($token), self::sameSiteClient(), FailureReason::REFRESH_TRANSPORT_MISMATCH],
            'a cross-site client' => [$cookie, self::crossSiteClient(), FailureReason::CROSS_SITE_REQUEST],
        ];
        $queries = 0;

        $this->recordEvents(self::EVENTS);

        DB::listen(static function () use (&$queries): void {
            $queries++;
        });

        foreach ($cases as $case => [$presented, $client, $reason]) {
            self::assertSame($reason, $service->refreshCredential($presented, $client), $case);
        }

        self::assertSame(0, $queries);
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A replay revokes its session, reported only by the revocation's
     * `SessionRevoked`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReplayRevokesItsSessionAndIsReportedOnlyByTheRevocation(): void
    {
        $this->seedIdentity();

        $session  = $this->signedIn();
        $replaced = self::refreshOf($session);

        self::assertTrue($this->sessions()->refresh(PresentedRefreshToken::fromBody($replaced), self::requestClient())->isRefreshed());

        $this->moveTo(CarbonImmutable::now()->addMinutes(2));
        $this->recordEvents(self::EVENTS);

        self::assertSame(FailureReason::ROTATION_REUSE, $this->serving(body: ['refresh_token' => $replaced])->refreshCredential(self::servedToken(), self::requestClient()));
        self::assertSame([SessionRevoked::class], $this->recordedClasses());
        self::assertSame(RevocationReason::ROTATION_REUSE, $this->recordedEvent(SessionRevoked::class)->reason);
        self::assertSame('rotation_reuse', Session::query()->whereKey($session->record->getKey())->value('revoked_reason'));
    }

    /**
     * Configure the session guards, `admin` a cookie application.
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

        $config->set('auth.guards.' . self::COOKIE . '.refresh_token', ['transport' => 'cookie', 'cookie' => ['path' => '/auth']]);
    }

    /**
     * The refresh token a body application's session carries.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return string
     */
    private static function refreshOf(SignedInSession $session): string
    {
        $token = $session->tokens->refreshToken?->reveal();

        self::assertIsString($token);

        return $token;
    }

    /**
     * Sign the identity with the email in on the guard.
     *
     * @param  string  $guard
     * @param  string  $email
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(string $guard = 'api', string $email = 'ada@example.test'): SignedInSession
    {
        $session = $this->sessions($guard)->signIn('password', self::credentials($email), self::requestContext())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * The session service of the guard, on a guard resolved afresh for a
     * request from the test client with the server values and body.
     *
     * @param  array<string, string>  $server
     * @param  array<string, string>  $body
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionService
     */
    private function serving(array $server = [], array $body = [], string $guard = 'api'): SessionService
    {
        app()->instance('request', Request::create('/sessions/me', 'POST', $body, server: [
            'REMOTE_ADDR'     => self::CLIENT_IP,
            'HTTP_USER_AGENT' => self::CLIENT_AGENT,
            ...$server,
        ]));

        Auth::forgetGuards();

        return Auth::sessions($guard);
    }

    /**
     * Bind a tenant authentication policy that answers with the requirement,
     * leaving the default check, which meets no further factor.
     *
     * @param  \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement  $requirement
     * @return \Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy
     */
    private function tenantPolicy(TenantRequirement $requirement): ScriptedTenantAuthenticationPolicy
    {
        $policy = new ScriptedTenantAuthenticationPolicy($requirement);

        app()->instance(TenantAuthenticationPolicy::class, $policy);

        return $policy;
    }

    /**
     * Move the clock, and the token library's, to the moment.
     *
     * @param  \Carbon\CarbonImmutable  $now
     * @return void
     */
    private function moveTo(CarbonImmutable $now): void
    {
        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();
    }
}
