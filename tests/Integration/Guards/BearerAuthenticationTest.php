<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\BearerAuthentication;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\SessionRecords\OwnedSession;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Fixtures\Tenancy\DescendantTenants;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * End-to-end tests for the events of a request's access token, against a real
 * database on whichever engine the suite runs on. A request's token is an
 * authentication, not a sign-in: it reports only `Authenticated` and the
 * package's contextual events, and a rejected one only `AuthenticationFailed`
 * with the reason the real rows give, never Laravel's `Attempting`,
 * `Validated`, `Login` or `Failed`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BearerAuthentication::class)]
#[CoversClass(OwnedSession::class)]
#[CoversClass(JwtGuard::class)]
final class BearerAuthenticationTest extends TestCase
{
    use InteractsWithSessions;

    /** @var list<class-string> Every event a bearer request could dispatch. */
    private const array OBSERVED = [
        Attempting::class,
        Validated::class,
        Login::class,
        Failed::class,
        Authenticated::class,
        PrincipalAssigned::class,
        SessionAuthenticated::class,
        SignedIn::class,
        AuthenticationFailed::class,
    ];

    /**
     * Freeze the clocks, create the tables, and add a route behind the `auth`
     * middleware of each guard.
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

        Route::middleware('auth:api')->get('/me', static fn (): array => ['identity' => Auth::id()]);
        Route::middleware('auth:members')->get('/members/me', static fn (): array => ['identity' => Auth::guard('members')->id()]);
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
     * A valid access token authenticates the request with exactly
     * `Authenticated`, `PrincipalAssigned` and `SessionAuthenticated`, which
     * carry the guard, the request's client, the identity, the session and the
     * method it records.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABearerRequestReportsOnlyTheAuthentication(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn();

        $this->recordEvents(self::OBSERVED);

        $this->bearer($session->tokens->accessToken->reveal())->assertOk()->assertJson(['identity' => $identity->getKey()]);

        self::assertSame([Authenticated::class, PrincipalAssigned::class, SessionAuthenticated::class], $this->recordedClasses());

        $context = $this->recordedEvent(SessionAuthenticated::class)->context;

        self::assertSame('api', $context->guard);
        self::assertSame('198.51.100.20', $context->client->ip);
        self::assertSame('Bearer/1.0', $context->client->userAgent);
        self::assertSame((string) $identity->getKey(), $context->identityId); // @phpstan-ignore cast.string
        self::assertSame($session->record->getKey(), $context->sessionId);
        self::assertSame('password', $context->method);
        self::assertSame($context, $this->recordedEvent(PrincipalAssigned::class)->context);
    }

    /**
     * A member's token reports the tenant its membership's activity check
     * loaded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABearerRequestReportsTheTenant(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext())->session;

        self::assertNotNull($session);

        $this->recordEvents([PrincipalAssigned::class]);

        $this->bearer($session->tokens->accessToken->reveal(), '/members/me')->assertOk()->assertJson(['identity' => $member->getKey()]);

        $context = $this->recordedEvent(PrincipalAssigned::class)->context;

        self::assertSame((string) $membership->getKey(), $context->principalId); // @phpstan-ignore cast.string
        self::assertSame((string) $tenant->getKey(), $context->tenantId); // @phpstan-ignore cast.string
    }

    /**
     * A token for a session acting in a tenant below the member's own reports
     * that tenant, resolved from the row, and never the membership's own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABearerRequestReportsTheTenantTheSessionActsIn(): void
    {
        [$member, $membership, $own] = $this->seedMember();

        $tree       = new DescendantTenants;
        $descendant = ActivatableTenant::query()->create(['name' => 'Descendant', 'is_active' => true]);

        $tree->place(self::modelKey($descendant), self::modelKey($own));

        app()->instance(TenantAccess::class, $tree);
        app()->instance(TenantResolver::class, $tree);

        $context = new SignInContext(ClientContext::fromRequest(Request::create('/')), tenant: TenantSelection::of(self::modelKey($descendant)));
        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), $context)->session;

        self::assertNotNull($session);

        $this->recordEvents([PrincipalAssigned::class]);

        $this->bearer($session->tokens->accessToken->reveal(), '/members/me')->assertOk()->assertJson(['identity' => $member->getKey()]);

        $assigned = $this->recordedEvent(PrincipalAssigned::class)->context;

        self::assertSame((string) $membership->getKey(), $assigned->principalId); // @phpstan-ignore cast.string
        self::assertSame((string) $descendant->getKey(), $assigned->tenantId); // @phpstan-ignore cast.string
    }

    /**
     * A bearer request checks the tenant the session acts in without asking
     * `TenantAccess`: access is decided at sign-in, on a switch and on refresh,
     * never per request.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABearerRequestNeverAsksTenantAccess(): void
    {
        [, , $own] = $this->seedMember();

        $tree       = new DescendantTenants;
        $descendant = ActivatableTenant::query()->create(['name' => 'Descendant', 'is_active' => true]);

        $tree->place(self::modelKey($descendant), self::modelKey($own));

        app()->instance(TenantAccess::class, $tree);
        app()->instance(TenantResolver::class, $tree);

        $context = new SignInContext(ClientContext::fromRequest(Request::create('/')), tenant: TenantSelection::of(self::modelKey($descendant)));
        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), $context)->session;

        self::assertNotNull($session);

        $access = \Mockery::mock(TenantAccess::class);
        $access->shouldNotReceive('mayActIn');

        app()->instance(TenantAccess::class, $access);

        $this->bearer($session->tokens->accessToken->reveal(), '/members/me')->assertOk();
    }

    /**
     * A request without a token attempts nothing and dispatches nothing.
     *
     * @return void
     */
    public function testARequestWithoutATokenDispatchesNothing(): void
    {
        $this->recordEvents(self::OBSERVED);

        $this->getJson('/me')->assertUnauthorized();

        self::assertSame([], $this->recorded);
    }

    /**
     * Rows of `[what the rows say, the reason]`: each way the real rows make a
     * token fail, after it was issued.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\Tests\Integration\Fixtures\IntegrationIdentity, \SineMacula\Laravel\Authentication\Sessions\SignedInSession): ?string, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideRejections(): iterable
    {
        yield 'a token that is not one' => [static fn (): string => 'not-a-jwt', FailureReason::TOKEN_INVALID];
        yield 'a deleted identity' => [static function (IntegrationIdentity $identity): ?string {
            $identity->delete();

            return null;
        }, FailureReason::IDENTITY_UNKNOWN];
        yield 'a deactivated identity' => [static function (IntegrationIdentity $identity): ?string {
            $identity->forceFill(['is_active' => false])->save();

            return null;
        }, FailureReason::IDENTITY_INACTIVE];
        yield 'another identity named as the principal' => [static function (IntegrationIdentity $identity, SignedInSession $session): string {
            $other = new IntegrationIdentity;
            $other->forceFill(['email' => 'grace@example.test', 'password' => 'x', 'is_active' => true])->save();

            $tokens = Auth::jwt('api');

            self::assertNotNull($tokens);

            return $tokens->issueAccessToken($identity, $other, null, $session->record)->reveal();
        }, FailureReason::PRINCIPAL_MISMATCH];
        yield 'a deleted session' => [static function (IntegrationIdentity $identity, SignedInSession $session): ?string {
            Session::query()->whereKey($session->record->getKey())->delete();

            return null;
        }, FailureReason::SESSION_UNKNOWN];
        yield 'a session of another guard' => [static function (IntegrationIdentity $identity, SignedInSession $session): ?string {
            Session::query()->whereKey($session->record->getKey())->update(['guard' => 'admin']);

            return null;
        }, FailureReason::SESSION_GUARD_MISMATCH];
        yield 'a revoked session' => [static function (IntegrationIdentity $identity, SignedInSession $session): ?string {
            Session::query()->whereKey($session->record->getKey())->update(['revoked_at' => Carbon::now(), 'revoked_reason' => 'revoked']);

            return null;
        }, FailureReason::SESSION_REVOKED];
        yield 'an ended session' => [static function (IntegrationIdentity $identity, SignedInSession $session): ?string {
            Session::query()->whereKey($session->record->getKey())->update(['idle_expires_at' => Carbon::now()]);

            return null;
        }, FailureReason::SESSION_EXPIRED];
        yield 'a session acting as another principal' => [static function (IntegrationIdentity $identity, SignedInSession $session): ?string {
            Session::query()->whereKey($session->record->getKey())->update(['principal_id' => 'another-principal']);

            return null;
        }, FailureReason::SESSION_PRINCIPAL_MISMATCH];
        yield 'a session acting as no principal' => [static function (IntegrationIdentity $identity, SignedInSession $session): ?string {
            Session::query()->whereKey($session->record->getKey())->update(['principal_type' => null, 'principal_id' => null]);

            return null;
        }, FailureReason::SESSION_PRINCIPAL_MISMATCH];
        yield 'a revoked session acting as another principal' => [static function (IntegrationIdentity $identity, SignedInSession $session): ?string {
            Session::query()->whereKey($session->record->getKey())->update(['principal_id' => 'another-principal', 'revoked_at' => Carbon::now()]);

            return null;
        }, FailureReason::SESSION_REVOKED];
        yield 'a switch after the token was issued' => [static function (IntegrationIdentity $identity, SignedInSession $session): ?string {
            Session::query()->whereKey($session->record->getKey())->update(['switched_at' => Carbon::now()->addSecond()]);

            return null;
        }, FailureReason::SESSION_SWITCHED];
        yield 'a session acting in a tenant the token does not name' => [static function (IntegrationIdentity $identity, SignedInSession $session): ?string {
            Session::query()->whereKey($session->record->getKey())->update(['tenant_id' => 'another-tenant']);

            return null;
        }, FailureReason::SESSION_TENANT_MISMATCH];
        yield 'a revoked session acting in another tenant' => [static function (IntegrationIdentity $identity, SignedInSession $session): ?string {
            Session::query()->whereKey($session->record->getKey())->update(['tenant_id' => 'another-tenant', 'revoked_at' => Carbon::now()]);

            return null;
        }, FailureReason::SESSION_REVOKED];
        yield 'a session acting in another tenant as another principal' => [static function (IntegrationIdentity $identity, SignedInSession $session): ?string {
            Session::query()->whereKey($session->record->getKey())->update(['tenant_id' => 'another-tenant', 'principal_id' => 'another-principal']);

            return null;
        }, FailureReason::SESSION_TENANT_MISMATCH];
        yield 'a session acting as another principal since the token was issued' => [static function (IntegrationIdentity $identity, SignedInSession $session): ?string {
            Session::query()->whereKey($session->record->getKey())->update(['principal_id' => 'another-principal', 'switched_at' => Carbon::now()->addSecond()]);

            return null;
        }, FailureReason::SESSION_PRINCIPAL_MISMATCH];
    }

    /**
     * A token the rows reject is answered `401` and reported once, as
     * `AuthenticationFailed` for the bearer flow with the reason, attributed to
     * the guard and the client, and nothing else is dispatched.
     *
     * @param  \Closure(\Tests\Integration\Fixtures\IntegrationIdentity, \SineMacula\Laravel\Authentication\Sessions\SignedInSession): ?string  $change
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRejections')]
    public function testATokenTheRowsRejectIsReportedOnceWithItsReason(\Closure $change, FailureReason $reason): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn();
        $token    = $change($identity, $session) ?? $session->tokens->accessToken->reveal();

        $this->recordEvents(self::OBSERVED);

        $this->bearer($token)->assertUnauthorized();

        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(AuthenticationFlow::BEARER, $failure->flow);
        self::assertSame($reason, $failure->reason);
        self::assertSame('api', $failure->context->guard);
        self::assertSame('198.51.100.20', $failure->context->client->ip);
        self::assertNull($failure->identifier);
        self::assertNull($failure->retryAfter);
    }

    /**
     * A session failure is attributed to the identity, the principal and the
     * session the rows hold, with the method the session records; a missing
     * session keeps the id the token named.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionFailureCarriesTheContextItEstablished(): void
    {
        $identity  = $this->seedIdentity();
        $session   = $this->signedIn();
        $sessionId = $session->record->getKey();

        Session::query()->whereKey($sessionId)->update(['revoked_at' => Carbon::now(), 'revoked_reason' => 'revoked']);

        $this->recordEvents([AuthenticationFailed::class]);

        $this->bearer($session->tokens->accessToken->reveal())->assertUnauthorized();

        $revoked = $this->recordedEvent(AuthenticationFailed::class)->context;

        Session::query()->whereKey($sessionId)->delete();

        $this->recordEvents([AuthenticationFailed::class]);

        $this->bearer($session->tokens->accessToken->reveal())->assertUnauthorized();

        $missing = $this->recordedEvent(AuthenticationFailed::class)->context;

        self::assertSame((string) $identity->getKey(), $revoked->identityId); // @phpstan-ignore cast.string
        self::assertSame((string) $identity->getKey(), $revoked->principalId); // @phpstan-ignore cast.string
        self::assertSame($sessionId, $revoked->sessionId);
        self::assertSame('password', $revoked->method);
        self::assertSame($sessionId, $missing->sessionId);
        self::assertNull($missing->method);
    }

    /**
     * A switch away from a principal and back again does not revive the tokens
     * issued to it before the first switch: each switch is recorded on the
     * session, and a token issued before the last one is rejected as
     * `session_switched` even though the session records its principal again. A
     * token issued in the second of the switch back is accepted, as the
     * switch's own tokens are.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSwitchingAwayAndBackDoesNotReviveEarlierTokens(): void
    {
        $identity  = $this->seedIdentity();
        $session   = $this->signedIn();
        $sessionId = $session->record->getKey();
        $recorded  = Session::query()->findOrFail($sessionId)->only(['principal_type', 'principal_id']);
        $earlier   = $session->tokens->accessToken->reveal();

        $this->moveClocksTo(Carbon::now()->addMinute());

        Session::query()->whereKey($sessionId)->update(['principal_type' => 'membership', 'principal_id' => 'another-principal', 'switched_at' => Carbon::now()]);

        $this->bearer($earlier)->assertUnauthorized();

        $this->moveClocksTo(Carbon::now()->addMinute());

        Session::query()->whereKey($sessionId)->update([...$recorded, 'switched_at' => Carbon::now()]);

        $this->recordEvents([AuthenticationFailed::class]);

        $this->bearer($earlier)->assertUnauthorized();

        self::assertSame(FailureReason::SESSION_SWITCHED, $this->recordedEvent(AuthenticationFailed::class)->reason);

        $tokens = Auth::jwt('api');

        self::assertNotNull($tokens);

        $this->bearer($tokens->issueAccessToken($identity, $identity, null, Session::query()->findOrFail($sessionId))->reveal())->assertOk();
    }

    /**
     * A member whose tenant is deactivated after the token was issued is
     * rejected as `tenant_inactive`, attributed to the member and membership.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeactivatedTenantRejectsItsMembersTokens(): void
    {
        [$member, $membership] = $this->seedMember();

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), self::requestContext())->session;

        self::assertNotNull($session);

        ActivatableTenant::query()->update(['is_active' => false]);

        $this->recordEvents([AuthenticationFailed::class]);

        $this->bearer($session->tokens->accessToken->reveal(), '/members/me')->assertUnauthorized();

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(FailureReason::TENANT_INACTIVE, $failure->reason);
        self::assertSame('members', $failure->context->guard);
        self::assertSame((string) $member->getKey(), $failure->context->identityId); // @phpstan-ignore cast.string
        self::assertSame((string) $membership->getKey(), $failure->context->principalId); // @phpstan-ignore cast.string
        EventContextAssertions::assertTenant(null, $failure->context);
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
     * Sign the seeded identity in on a new session of the `api` guard.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(): SignedInSession
    {
        $session = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);
        self::assertSame(1, DB::table('authentication_sessions')->count());

        return $session;
    }

    /**
     * Move every clock to the time.
     *
     * @param  \Carbon\CarbonInterface  $time
     * @return void
     */
    private function moveClocksTo(CarbonInterface $time): void
    {
        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }

    /**
     * Send a request with the bearer token from a known client.
     *
     * @param  string  $token
     * @param  string  $uri
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(string $token, string $uri = '/me'): TestResponse
    {
        Auth::forgetGuards();

        return $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.20'])
            ->withHeaders(['Authorization' => 'Bearer ' . $token, 'User-Agent' => 'Bearer/1.0'])
            ->getJson($uri);
    }
}
