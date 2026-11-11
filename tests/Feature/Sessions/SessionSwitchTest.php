<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\RequirementCheck;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Contracts\TenantAccess;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\PrincipalSwitched;
use SineMacula\Laravel\Authentication\Events\SessionActivated;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Events\SessionReturnedToPending;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\NeverRequireAdditionalFactor;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementEvaluation;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use SineMacula\Laravel\Authentication\Sessions\Concerns\SwitchesSessions;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionSwitch;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal;
use SineMacula\Laravel\Authentication\Sessions\SwitchResult;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Support\PrincipalReference;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use Tests\Concerns\InspectsIssuanceGuards;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Events\EventContextAssertions;
use Tests\Fixtures\Factors\AlwaysRequireAdditionalFactor;
use Tests\Fixtures\Sessions\RefusingApplicationAccess;
use Tests\Fixtures\Tenancy\DescendantTenants;
use Tests\Fixtures\Tenancy\ProofJudgingRequirementCheck;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\Integration\Fixtures\IdentifierTypeOmittingSession;
use Tests\Integration\Fixtures\UnscopedMembershipResolver;
use Tests\TestCase;

/**
 * Feature tests of switching a session to another principal, another tenant, or
 * both, proven by its refresh token.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionSwitch::class)]
#[CoversClass(SessionService::class)]
#[CoversClass(SwitchedPrincipal::class)]
#[CoversClass(SwitchResult::class)]
#[CoversClass(PrincipalSwitched::class)]
#[CoversTrait(SwitchesSessions::class)]
final class SessionSwitchTest extends TestCase
{
    use InspectsIssuanceGuards, InteractsWithProofs, InteractsWithSessions;

    /** @var string Guard over `ActivatableTenantMember`. */
    private const string GUARD = 'members';

    /** @var string Cookie application over `ActivatableTenantMember`. */
    private const string BROWSER = 'browser_members';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /** @var ?\Tests\Fixtures\Tenancy\DescendantTenants The application's tree, once a test binds it as the tenant access and resolver. */
    private ?DescendantTenants $tree = null;

    /**
     * Freeze the clocks, create the tables and register the routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freezeAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();

        Route::post('/switch', static function (Request $request): array {

            $target = ActivatableTenantMembership::query()->findOrFail($request->integer('membership'));
            $result = Auth::sessions(self::GUARD)->switchTo(
                PresentedRefreshToken::fromBody($request->string('refresh')->toString()),
                SwitchTarget::principal($target),
                self::requestClient(),
            );
            $guard = app('auth')->guard(self::GUARD);

            assert($guard instanceof JwtGuard);

            return [
                'switched'  => $result->isSwitched(),
                'reason'    => $result->reason?->value,
                'access'    => $result->session?->tokens->accessToken->reveal(),
                'refresh'   => $result->session?->tokens->refreshToken?->reveal(),
                'principal' => $guard->principal()?->getPrincipalIdentifier(),
            ];
        });

        Route::post('/switch-extracted', static fn (Request $request): array => self::switchRoute($request));

        Route::middleware('auth:' . self::GUARD)->get('/me', static fn (): array => ['principal' => Auth::principal()?->getPrincipalIdentifier()]);
        Route::middleware('auth:' . self::GUARD)->get('/tenant', static fn (): array => ['tenant' => IdentifierCoercion::stringify(Auth::tenant()?->getTenantIdentifier())]);
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
     * A switch over HTTP refuses the old principal's access token at once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchOverHttpStopsTheOldAccessTokenAtOnce(): void
    {
        [$first, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        $switched = $this->switch(self::bodyRefreshToken($session->tokens), $second)->assertOk();

        $switched->assertJson(['switched' => true, 'reason' => null, 'principal' => $second->getKey()]);

        $this->bearer(self::tokenIn($switched, 'access'))->assertOk()->assertExactJson(['principal' => $second->getKey()]);
        $this->bearer($session->tokens->accessToken->reveal())->assertUnauthorized();

        self::assertNotSame($first->getKey(), $second->getKey());
    }

    /**
     * A switch read from the request takes the refresh token from the source
     * the guard allows and says which, from the body and then from the header.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchReadFromTheRequestSaysWhereItsTokenCameFrom(): void
    {
        [$first, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        $body = $this->postJson('/switch-extracted', ['refresh_token' => $session->tokens->refreshToken?->reveal(), 'membership' => $second->getKey()])
            ->assertOk()
            ->assertJson(['outcome' => 'switched', 'reason' => null, 'source' => 'body']);

        $this->advance(5);

        Auth::forgetGuards();

        $this->withHeaders(['X-Refresh-Token' => $body->json('refresh')])
            ->postJson('/switch-extracted', ['membership' => $first->getKey()])
            ->assertOk()
            ->assertJson(['outcome' => 'switched', 'source' => 'header']);
    }

    /**
     * A switch read from the request is refused by the transport before the
     * session is touched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchReadFromTheRequestIsRefusedByTheTransport(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->recordEvents([AuthenticationFailed::class, PrincipalSwitched::class]);

        Auth::forgetGuards();

        $this->postJson('/switch-extracted', ['membership' => $second->getKey()])
            ->assertOk()
            ->assertExactJson(['outcome' => 'none', 'reason' => null, 'source' => null, 'refresh' => null]);

        self::assertSame([], $this->recorded);

        Auth::forgetGuards();

        $this->withHeaders(['X-Refresh-Token' => $session->tokens->refreshToken?->reveal()])
            ->postJson('/switch-extracted', ['refresh_token' => $session->tokens->refreshToken?->reveal(), 'membership' => $second->getKey()])
            ->assertOk()
            ->assertJson(['outcome' => 'failed', 'reason' => 'refresh_token_conflict', 'source' => null]);

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(AuthenticationFlow::SWITCH, $failure->flow);
        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, $failure->reason);
        self::assertSame(self::GUARD, $failure->context->guard);
        EventContextAssertions::assertSession(null, $failure->context);
        self::assertSame(PrincipalReference::id($session->principal), DB::table('authentication_sessions')->value('principal_id'));
    }

    /**
     * A switch records the target on the session and reports
     * `PrincipalSwitched`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchRecordsTheTargetAndReportsTheSwitch(): void
    {
        ActivatableTenant::query()->create(['name' => 'Unrelated', 'is_active' => true]);

        [$first, $second, $member, $tenant] = $this->seedMemberships();

        self::assertNotEquals($first->getKey(), $tenant->getKey());

        $session  = $this->signIn();
        $absolute = DB::table('authentication_sessions')->value('absolute_expires_at');

        $this->advance(60);

        $this->recordEvents([Authenticated::class, PrincipalAssigned::class, SessionAuthenticated::class, PrincipalSwitched::class, Login::class]);

        $result = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::principal($second),
            self::requestClient(),
        );

        self::assertTrue($result->isSwitched());
        self::assertFalse($result->isFailed());
        self::assertNull($result->reason);
        self::assertNotNull($result->session);
        self::assertTrue($result->session->principal->is($second)); // @phpstan-ignore method.notFound
        self::assertTrue($result->session->identity->is($member)); // @phpstan-ignore method.notFound
        self::assertSame('password', $result->session->method);

        self::assertSame([PrincipalSwitched::class, Authenticated::class, PrincipalAssigned::class, SessionAuthenticated::class], $this->recordedClasses());

        $event = $this->recordedEvent(PrincipalSwitched::class);

        self::assertSame(self::GUARD, $event->context->guard);
        EventContextAssertions::assertPrincipal($second, $event->context);
        self::assertSame((string) $second->tenant_id, $event->context->tenantId);
        self::assertSame(ActivatableTenantMembership::class, $event->previousPrincipalType);
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), $event->previousPrincipalId);
        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $event->previousTenantId);
        self::assertTrue($event->principalChanged);
        self::assertTrue($event->tenantChanged);
        self::assertSame('password', $event->context->method);

        $record = DB::table('authentication_sessions')->sole();

        self::assertSame((string) $second->getKey(), (string) $record->principal_id); // @phpstan-ignore cast.string
        self::assertSame((string) $second->tenant_id, $record->tenant_id);
        self::assertSame($this->now->toDateTimeString(), CarbonImmutable::parse($record->switched_at)->toDateTimeString());
        self::assertSame($this->now->toDateTimeString(), CarbonImmutable::parse($record->refresh_rotated_at)->toDateTimeString());
        self::assertSame($absolute, $record->absolute_expires_at);
        self::assertSame($this->now->addMinutes(60 * 24 * 30)->toDateTimeString(), CarbonImmutable::parse($record->idle_expires_at)->toDateTimeString());

        self::assertTrue(Auth::guard(self::GUARD)->principal()?->is($second)); // @phpstan-ignore method.notFound
        self::assertSame(IdentifierCoercion::stringify($second->tenant_id), self::boundTenantId());

        $idle = $this->now->addMinutes(60 * 24 * 30)->getTimestamp();

        self::assertSame($idle, self::expiryOf(self::bodyRefreshToken($result->session->tokens)));
        self::assertSame($this->now->addMinutes(15)->getTimestamp(), self::expiryOf($result->session->tokens->accessToken->reveal()));
    }

    /**
     * The refresh token a sign-in returned switches its session when it is
     * handed in as the `Secret` it was returned as.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchTakesTheTokenAsTheSecretItWasReturnedAs(): void
    {
        [, $second] = $this->seedMemberships();

        $token = $this->signIn()->tokens->refreshToken;

        self::assertNotNull($token);

        $this->advance(60);

        $result = $this->sessions(self::GUARD)->switchTo(PresentedRefreshToken::fromBody($token), SwitchTarget::principal($second), self::requestClient());

        self::assertTrue($result->isSwitched());
        self::assertTrue($result->session?->principal->is($second)); // @phpstan-ignore method.notFound
    }

    /**
     * After A -> B -> A the access token issued for A before the first switch
     * stays refused, while the one the second switch issued is accepted.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSwitchingBackDoesNotRestoreTheOldTokens(): void
    {
        [$first, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        $toSecond = $this->switch(self::bodyRefreshToken($session->tokens), $second)->assertJson(['switched' => true]);

        $this->advance(5);

        $back = $this->switch(self::tokenIn($toSecond, 'refresh'), $first)->assertJson(['switched' => true, 'principal' => $first->getKey()]);

        $this->bearer($session->tokens->accessToken->reveal())->assertUnauthorized();
        $this->bearer(self::tokenIn($toSecond, 'access'))->assertUnauthorized();
        $this->bearer(self::tokenIn($back, 'access'))->assertOk()->assertExactJson(['principal' => $first->getKey()]);
    }

    /**
     * The old refresh token inside the grace window fails as
     * `session_principal_mismatch` without revoking.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheOldRefreshTokenInsideTheGraceWindowFailsWithoutRevoking(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        $switched = $this->switched($session, $second);

        $this->advance(5);

        $this->recordEvents([AuthenticationFailed::class, SessionRevoked::class]);

        self::assertNull(
            self::sessionsOf($this->freshGuard(self::GUARD))->refresh(self::bodyToken($session->tokens), self::requestClient())->session,
        );
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(FailureReason::SESSION_PRINCIPAL_MISMATCH, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertNull(DB::table('authentication_sessions')->value('revoked_at'));

        self::assertNotNull(
            self::sessionsOf($this->freshGuard(self::GUARD))->refresh(self::bodyToken($switched->tokens), self::requestClient())->session,
        );
    }

    /**
     * The old refresh token after the grace window revokes the session as
     * `rotation_reuse`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheOldRefreshTokenAfterTheGraceWindowRevokesTheSession(): void
    {
        [$first, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);
        $this->switched($session, $second);
        $this->advance(31);

        $this->recordEvents([AuthenticationFailed::class, SessionRevoked::class]);

        $result = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::principal($first),
            self::requestClient(),
        );

        self::assertTrue($result->isFailed());
        self::assertSame(FailureReason::ROTATION_REUSE, $result->reason);
        self::assertSame([SessionRevoked::class, AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(RevocationReason::ROTATION_REUSE, $this->recordedEvent(SessionRevoked::class)->reason);
        self::assertSame(self::CLIENT_IP, $this->recordedEvent(SessionRevoked::class)->context->client->ip);
        self::assertSame(IdentifierCoercion::stringify($second->getKey()), $this->recordedEvent(SessionRevoked::class)->context->principalId);

        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(AuthenticationFlow::SWITCH, $failed->flow);
        self::assertSame(self::GUARD, $failed->context->guard);
        self::assertSame('password', $failed->context->method);
        self::assertSame('rotation_reuse', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * A lost switch response is answered again inside the grace window.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALostSwitchResponseIsAnsweredAgainInsideTheGraceWindow(): void
    {
        [$first, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);
        $this->switched($session, $second);

        $row = self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->sole());

        $this->advance(5);

        $this->recordEvents([PrincipalSwitched::class, AuthenticationFailed::class, SessionRevoked::class]);

        $retried = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::principal($second),
            self::requestClient(),
        );

        self::assertTrue($retried->isSwitched());
        self::assertTrue($retried->session?->principal->is($second)); // @phpstan-ignore method.notFound
        self::assertSame([], $this->recordedClasses());
        self::assertEquals($row, self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->sole()));

        $this->advance(1);

        $conflict = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::principal($first),
            self::requestClient(),
        );

        self::assertSame(FailureReason::ROTATION_CONFLICT, $conflict->reason);

        DB::table('authentication_sessions')->update(['switched_at' => $this->now->subMinute()]);

        self::assertSame(
            FailureReason::ROTATION_CONFLICT,
            $this->sessions(self::GUARD)->switchTo(
                self::bodyToken($session->tokens),
                SwitchTarget::principal($second),
                self::requestClient(),
            )->reason,
        );

        DB::table('authentication_sessions')->update(['switched_at' => $row['switched_at']]);

        $this->bearer($retried->session->tokens->accessToken->reveal())->assertOk()->assertExactJson(['principal' => $second->getKey()]);
        self::assertNotNull(
            self::sessionsOf($this->freshGuard(self::GUARD))->refresh(
                self::bodyToken($retried->session->tokens),
                self::requestClient(),
            )->session,
        );
        self::assertNull(DB::table('authentication_sessions')->value('revoked_at'));
    }

    /**
     * A switch away from a principal that no longer resolves for the identity
     * still reports what the session recorded for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchFromAPrincipalThatIsGoneReportsItsSnapshot(): void
    {
        [$first, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $first->delete();

        $this->recordEvents([PrincipalSwitched::class]);

        self::assertTrue(
            $this->sessions(self::GUARD)->switchTo(
                self::bodyToken($session->tokens),
                SwitchTarget::principal($second),
                self::requestClient(),
            )->isSwitched(),
        );

        $event = $this->recordedEvent(PrincipalSwitched::class);

        self::assertSame(ActivatableTenantMembership::class, $event->previousPrincipalType);
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), $event->previousPrincipalId);
    }

    /**
     * A switch from a principal recorded under another type reports the
     * recorded snapshot.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchFromAPrincipalOfAnotherTypeReportsOnlyItsSnapshot(): void
    {
        [$first, $second] = $this->seedMemberships();

        $session = $this->signIn();

        DB::table('authentication_sessions')->update(['principal_type' => 'retired-membership']);

        $this->recordEvents([PrincipalSwitched::class]);

        self::assertTrue(
            $this->sessions(self::GUARD)->switchTo(
                self::bodyToken($session->tokens),
                SwitchTarget::principal($second),
                self::requestClient(),
            )->isSwitched(),
        );

        $event = $this->recordedEvent(PrincipalSwitched::class);

        self::assertSame('retired-membership', $event->previousPrincipalType);
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), $event->previousPrincipalId);
    }

    /**
     * A switch to no tenant records none and is answered again inside the grace
     * window.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchToNoTenantRecordsNoneAndIsAnsweredAgain(): void
    {
        [, , , $own] = $this->seedMemberships();

        $this->allowEveryTenant();

        $session = $this->signIn();

        $this->advance(5);
        $this->recordEvents([PrincipalSwitched::class]);

        $switched = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::tenant(TenantSelection::none()),
            self::requestClient(),
        );

        self::assertTrue($switched->isSwitched());
        self::assertNull(DB::table('authentication_sessions')->value('tenant_id'));
        self::assertSame(IdentifierCoercion::stringify($own->getKey()), $this->recordedEvent(PrincipalSwitched::class)->previousTenantId);
        EventContextAssertions::assertTenant(null, $this->recordedEvent(PrincipalSwitched::class)->context);

        $this->advance(5);

        $retried = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::tenant(TenantSelection::none()),
            self::requestClient(),
        );

        self::assertTrue($retried->isSwitched());
        self::assertNull(DB::table('authentication_sessions')->value('tenant_id'));
    }

    /**
     * A token whose rotation id is not a string is refused as `token_invalid`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenWithoutAStringRotationIdIsRefused(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();
        $claims  = self::claimsOf(self::bodyRefreshToken($session->tokens));
        $forged  = JWT::encode([...$claims, 'jti' => 42], 'test-secret-key-with-at-least-32-bytes!', 'HS256', 'test-kid', ['typ' => TokenType::REFRESH->value]);

        self::assertNotNull(Auth::jwt(self::GUARD)->parse($forged, TokenType::REFRESH));

        $this->assertSwitchFails(FailureReason::TOKEN_INVALID, $session, $second, $forged);
    }

    /**
     * A refresh token one refresh old is answered again only for its own
     * principal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPreviousRefreshTokenIsAnsweredOnlyForItsOwnPrincipal(): void
    {
        [$first, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        self::assertNotNull(
            self::sessionsOf($this->freshGuard(self::GUARD))->refresh(self::bodyToken($session->tokens), self::requestClient())->session,
        );

        $own = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::principal($first),
            self::requestClient(),
        );

        self::assertTrue($own->isSwitched());
        self::assertTrue($own->session?->principal->is($first)); // @phpstan-ignore method.notFound

        self::assertSame(
            FailureReason::ROTATION_CONFLICT,
            $this->sessions(self::GUARD)->switchTo(
                self::bodyToken($session->tokens),
                SwitchTarget::principal($second),
                self::requestClient(),
            )->reason,
        );
    }

    /**
     * A switch to the current principal rotates the credential like a refresh.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchToTheCurrentPrincipalRotatesLikeARefresh(): void
    {
        [$first] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        $this->recordEvents([PrincipalSwitched::class]);

        $result = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::principal($first),
            self::requestClient(),
        );

        self::assertTrue($result->isSwitched());
        self::assertSame([], $this->recordedClasses());
        self::assertNull(DB::table('authentication_sessions')->value('switched_at'));
        self::assertSame($this->now->toDateTimeString(), $this->storedTime('refresh_rotated_at'));

        $this->bearer($session->tokens->accessToken->reveal())->assertOk();
        $this->bearer((string) $result->session?->tokens->accessToken->reveal())->assertOk();
    }

    /**
     * A target the identity may not act as is refused, naming the session's
     * owner and the target.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATargetTheIdentityMayNotActAsIsRefused(): void
    {
        [, $second, $member, $tenant] = $this->seedMemberships();

        [, $theirs] = $this->seedMember('other@example.test', $tenant);

        $session = $this->signIn();
        $row     = self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->sole());

        $mismatch = $this->assertSwitchFails(FailureReason::PRINCIPAL_MISMATCH, $session, $theirs);

        self::assertSame(IdentifierCoercion::stringify($member->getKey()), $mismatch->context->identityId);
        EventContextAssertions::assertPrincipal(null, $mismatch->context);
        self::assertNull($mismatch->context->principalType);
        self::assertNull($mismatch->context->principalId);
        self::assertSame(IdentifierCoercion::stringify($session->record->getSessionIdentifier()), $mismatch->context->sessionId);

        $this->assertSwitchFails(FailureReason::PRINCIPAL_MISMATCH, $session, ChoosingMembership::query()->findOrFail(self::modelKey($second)));

        ActivatableTenant::query()->whereKey($second->tenant_id)->update(['is_active' => false]);

        $inactive = $this->assertSwitchFails(FailureReason::TENANT_INACTIVE, $session, $second);

        self::assertSame(IdentifierCoercion::stringify($second->getKey()), $inactive->context->principalId);
        self::assertEquals($row, self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->sole()));
    }

    /**
     * A target `ApplicationAccess` keeps out is refused as
     * `principal_ineligible`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATargetTheAccessRefusesIsRefused(): void
    {
        [, $second] = $this->seedMemberships();

        self::refuseTenantsPrincipals($second->tenant_id);

        $session = $this->signIn();
        $row     = self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->sole());
        $refused = $this->assertSwitchFails(FailureReason::PRINCIPAL_INELIGIBLE, $session, $second);

        self::assertSame(IdentifierCoercion::stringify($second->getKey()), $refused->context->principalId);
        self::assertEquals($row, self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->sole()));
    }

    /**
     * A switch is refused as `method_not_allowed` once the session's method is
     * no longer listed.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchIsRefusedOnceTheSessionsMethodIsNoLongerAllowed(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();
        $row     = self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->sole());

        foreach ([['sso'], []] as $methods) {
            config()->set('auth.guards.' . self::GUARD . '.application.methods', $methods);

            $this->assertSwitchFails(FailureReason::METHOD_NOT_ALLOWED, $session, $second);

            self::assertEquals($row, self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->sole()));
        }

        config()->set('auth.guards.' . self::GUARD . '.application.methods', ['password']);

        self::assertSame($second->getKey(), $this->switched($session, $second)->principal->getPrincipalIdentifier());
    }

    /**
     * A session loaded without its identifier type is reported rather than
     * switched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionLoadedWithoutItsIdentifierTypeIsReported(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();
        $row     = self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->sole());

        config()->set('authentication.session.model', IdentifierTypeOmittingSession::class);

        try {
            $this->sessions(self::GUARD)->switchTo(
                self::bodyToken($session->tokens),
                SwitchTarget::principal($second),
                self::requestClient(),
            );

            self::fail('The switch read a session without its identifier type.');
        } catch (\LogicException $exception) {
            self::assertStringContainsString('its `sign_in_identifier_type` attribute is not loaded', $exception->getMessage());
        }

        self::assertEquals($row, self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->sole()));
    }

    /**
     * A switch screen lists only the targets the switch admits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchScreenListsOnlyTheTargetsTheSwitchAdmits(): void
    {
        [$first, $second, $member] = $this->seedMemberships();

        self::refuseTenantsPrincipals($second->tenant_id);

        $session = $this->signIn();
        $guard   = Auth::manager()->guard(self::GUARD);

        assert($guard instanceof JwtGuard);

        $type   = $guard->session()?->getSignInIdentifierType();
        $listed = $this->sessions(self::GUARD)->principals($member, $type);

        self::assertSame('email', $type);
        self::assertSame([$first->getKey()], array_map(static fn (Principal $principal): mixed => $principal->getPrincipalIdentifier(), $listed));
        self::assertCount(1, $this->sessions(self::GUARD)->principals($member));
        $this->assertSwitchFails(FailureReason::PRINCIPAL_INELIGIBLE, $session, $second);
    }

    /**
     * A switch is refused when the application policy now refuses the session's
     * identifier for the identity.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentifierThePolicyRefusesTheIdentityRefusesTheSwitch(): void
    {
        [, $second, $member] = $this->seedMemberships();

        $session = $this->signIn();
        $row     = self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->sole());
        $package = app(ApplicationPolicy::class);

        $policy = \Mockery::mock(ApplicationPolicy::class);
        $policy->shouldReceive('allowsMethod')->andReturnUsing($package->allowsMethod(...));
        $policy->shouldReceive('lifetimes')->andReturnUsing($package->lifetimes(...));
        $policy->shouldReceive('admitIdentifier')
            ->once()
            ->with(self::GUARD, \Mockery::on(static fn (Identity $identity): bool => $identity->getAuthIdentifier() === $member->getKey()), 'email')
            ->andReturn(FailureReason::IDENTIFIER_UNVERIFIED);

        app()->instance(ApplicationPolicy::class, $policy);

        $this->assertSwitchFails(FailureReason::IDENTIFIER_UNVERIFIED, $session, $second);

        self::assertEquals($row, self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->sole()));
    }

    /**
     * A target an unscoped resolver hands back must still be the identity's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATargetAnUnscopedResolverHandsBackMustStillBeTheIdentitys(): void
    {
        [, , , $tenant] = $this->seedMemberships();

        [, $theirs] = $this->seedMember('other@example.test', $tenant);

        config()->set('auth.guards.' . self::GUARD . '.principal_resolver', UnscopedMembershipResolver::class);

        $this->assertSwitchFails(FailureReason::PRINCIPAL_MISMATCH, $this->signIn(), $theirs);
    }

    /**
     * A token that proves no session of the guard is refused before anything is
     * written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenThatProvesNoSessionOfTheGuardIsRefused(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->assertSwitchFails(FailureReason::TOKEN_INVALID, $session, $second, $session->tokens->accessToken->reveal());

        DB::table('authentication_sessions')->update(['guard' => 'admin']);

        $this->assertSwitchFails(FailureReason::SESSION_GUARD_MISMATCH, $session, $second);

        self::assertSame(0, self::issuanceGuardWrites($session->record->getKey()));

        DB::table('authentication_sessions')->delete();

        $this->assertSwitchFails(FailureReason::SESSION_UNKNOWN, $session, $second);
    }

    /**
     * Rows of `[whether the switch returns the session to pending]`.
     *
     * @return iterable<string, array{0: bool}>
     */
    public static function provideSwitchOutcomes(): iterable
    {
        yield 'switched' => [false];
        yield 'returned to pending' => [true];
    }

    /**
     * A switch whose destination is deactivated before it commits ends the
     * session.
     *
     * @param  bool  $pending
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideSwitchOutcomes')]
    public function testASwitchWhoseDestinationIsDeactivatedBeforeItCommitsEndsTheSession(bool $pending): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();
        $policy  = new ScriptedTenantAuthenticationPolicy;

        $policy->answer = static function (TenantPolicyContext $context) use ($second, $pending): TenantRequirement {
            ActivatableTenant::query()->whereKey($second->tenant_id)->update(['is_active' => false]);

            return $pending ? new TenantRequirement('v1', new Requirement(new RequirementPart)) : new TenantRequirement;
        };

        app()->instance(TenantAuthenticationPolicy::class, $policy);

        $this->recordEvents([AuthenticationFailed::class, PrincipalSwitched::class, SessionReturnedToPending::class, SessionRevoked::class]);

        $result = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::principal($second),
            self::requestClient(),
        );
        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(FailureReason::TENANT_INACTIVE, $result->reason);
        self::assertSame([SessionRevoked::class, AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(AuthenticationFlow::SWITCH, $failed->flow);
        self::assertSame(IdentifierCoercion::stringify($session->record->getKey()), $failed->context->sessionId);
        self::assertSame('password', $failed->context->method);
        self::assertSame(RevocationReason::TENANT_DEACTIVATED->value, Session::query()->whereKey($session->record->getKey())->value('revoked_reason'));
    }

    /**
     * A session switched and switched back inside a transaction is not ended by
     * the tenant it left.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionSwitchedOnInsideATransactionIsNotEndedByWhatItLeft(): void
    {
        [$first, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        DB::beginTransaction();

        $toSecond = $this->switched($session, $second);

        $this->advance(5);

        $back = $this->switchedTo((string) $toSecond->tokens->refreshToken?->reveal(), SwitchTarget::principal($first));

        ActivatableTenant::query()->whereKey($second->tenant_id)->update(['is_active' => false]);

        DB::commit();

        self::assertTrue($back->principal->is($first)); // @phpstan-ignore method.notFound
        self::assertNull(Session::query()->whereKey($session->record->getKey())->value('revoked_reason'));
    }

    /**
     * A session signed in and switched inside a transaction is judged on where
     * it acts at the commit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionSignedInAndSwitchedInsideATransactionIsJudgedOnWhereItActs(): void
    {
        [$first, $second] = $this->seedMemberships();

        DB::beginTransaction();

        $left = $this->signIn();

        $this->advance(5);

        $this->switched($left, $second);

        ActivatableTenant::query()->whereKey($first->tenant_id)->update(['is_active' => false]);

        DB::commit();

        self::assertNull(Session::query()->whereKey($left->record->getKey())->value('revoked_reason'));

        ActivatableTenant::query()->whereKey($first->tenant_id)->update(['is_active' => true]);

        DB::beginTransaction();

        $ended = $this->signIn();

        $this->advance(5);

        $this->switched($ended, $second);

        ActivatableTenant::query()->whereKey($second->tenant_id)->update(['is_active' => false]);

        DB::commit();

        self::assertSame(RevocationReason::TENANT_DEACTIVATED->value, Session::query()->whereKey($ended->record->getKey())->value('revoked_reason'));
    }

    /**
     * A switch runs in one transaction opened by the session's issuance guard.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchRunsInATransactionTheIssuanceGuardOpens(): void
    {
        [, $second] = $this->seedMemberships();

        $session    = $this->signIn();
        $later      = $this->now->addSeconds(2);
        $statements = [];

        DB::listen(function (QueryExecuted $query) use (&$statements, $later): void {
            $statements[] = [$query->sql, $query->connection->transactionLevel()];

            if (!str_contains($query->sql, 'issuance_sequence')) {
                return;
            }

            $this->freezeAt($later);
        });

        $this->switched($session, $second);

        $guard = array_key_first(array_filter($statements, static fn (array $statement): bool => str_contains($statement[0], 'issuance_sequence')));

        self::assertIsInt($guard);
        self::assertSame(0, $statements[$guard - 1][1]);
        self::assertSame([1], array_values(array_unique(array_column(array_slice($statements, $guard, -3), 1))));
        self::assertSame([0, 0], array_column(array_slice($statements, -2), 1));
        self::assertSame(['select', 'select'], array_map(static fn (string $sql): string => strtolower(strtok($sql, ' ') ?: ''), array_column(array_slice($statements, -2), 0)));
        self::assertStringContainsString('group by', implode(' | ', array_column(array_slice($statements, $guard), 0)));
        self::assertSame(0, DB::transactionLevel());
        self::assertSame(1, self::issuanceGuardWrites($session->record->getKey()));
        self::assertSame($later->toDateTimeString(), $this->storedTime('refresh_rotated_at'));
    }

    /**
     * A session deleted between the switch's lookup and its issuance guard
     * fails as `session_unknown`, as one the lookup never found does.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionGoneBeforeTheGuardIsUnknown(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();
        $ran     = false;

        DB::connection()->beforeExecuting(static function (string $query) use (&$ran): void {
            if ($ran || !str_contains($query, 'issuance_sequence')) {
                return;
            }

            $ran = true;

            DB::table('authentication_sessions')->delete();
        });

        $failure = $this->assertSwitchFails(FailureReason::SESSION_UNKNOWN, $session, $second);

        self::assertTrue($ran);
        self::assertSame(IdentifierCoercion::stringify($session->record->getKey()), $failure->context->sessionId);
    }

    /**
     * Rows of `[the change committed before the guard, the failure]`.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideChangesBeforeTheGuard(): iterable
    {
        yield 'revoked' => [['revoked_at' => '2026-04-06 11:59:59', 'revoked_reason' => 'signed_out'], FailureReason::SESSION_REVOKED];

        yield 'returned to pending' => [['status' => 'pending'], FailureReason::SESSION_PENDING];
    }

    /**
     * A grace retry is judged on the row read after the issuance guard.
     *
     * @param  array<string, mixed>  $change
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChangesBeforeTheGuard')]
    public function testAGraceRetryIsJudgedOnTheRowReadAfterTheGuard(array $change, FailureReason $reason): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);
        $this->switched($session, $second);
        $this->advance(5);

        $ran = false;

        DB::connection()->beforeExecuting(static function (string $query) use (&$ran, $change): void {
            if ($ran || !str_contains($query, 'issuance_sequence')) {
                return;
            }

            $ran = true;

            DB::table('authentication_sessions')->update($change);
        });

        $this->assertSwitchFails($reason, $session, $second);

        self::assertTrue($ran);
    }

    /**
     * A grace retry after a switch the issuance guard waited for is a replay.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGraceRetryAfterASwitchTheGuardWaitedForIsAReplay(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);
        $this->switched($session, $second);
        $this->advance(5);

        $rotation = self::claimsOf((string) $session->tokens->refreshToken?->reveal())['jti'];

        self::assertIsString($rotation);

        $ran = false;

        DB::connection()->beforeExecuting(function (string $query) use (&$ran, $rotation): void {
            if ($ran || !str_contains($query, 'issuance_sequence')) {
                return;
            }

            $ran = true;

            DB::table('authentication_sessions')->update([
                'refresh_key'          => RefreshTokenHasher::hash(RefreshTokenHasher::successor(RefreshTokenHasher::successor($rotation))),
                'previous_refresh_key' => RefreshTokenHasher::hash(RefreshTokenHasher::successor($rotation)),
                'refresh_rotated_at'   => $this->now,
            ]);
        });

        $this->recordEvents([AuthenticationFailed::class, SessionRevoked::class]);

        $result = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::principal($second),
            self::requestClient(),
        );

        self::assertTrue($ran);
        self::assertTrue($result->isFailed());
        self::assertNull($result->session);
        self::assertSame(FailureReason::ROTATION_REUSE, $result->reason);
        self::assertSame([SessionRevoked::class, AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(RevocationReason::ROTATION_REUSE, $this->recordedEvent(SessionRevoked::class)->reason);
        self::assertSame('rotation_reuse', DB::table('authentication_sessions')->value('revoked_reason'));
        self::assertNull(DB::table('authentication_sessions')->value('refresh_key'));
    }

    /**
     * A switch on a revoked or ended session is refused, naming what the row
     * records.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchOnAnEndedSessionIsRefused(): void
    {
        [$first, $second, $member] = $this->seedMemberships();

        $session = $this->signIn();

        DB::table('authentication_sessions')->update(['idle_expires_at' => $this->now->subSecond()]);

        $this->assertSwitchFails(FailureReason::SESSION_EXPIRED, $session, $second);

        DB::table('authentication_sessions')->update(['revoked_at' => $this->now, 'revoked_reason' => 'revoked']);

        $revoked = $this->assertSwitchFails(FailureReason::SESSION_REVOKED, $session, $second);

        self::assertSame(IdentifierCoercion::stringify($member->getKey()), $revoked->context->identityId);
        self::assertSame($first->getMorphClass(), $revoked->context->principalType);
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), $revoked->context->principalId);
    }

    /**
     * A switch whose token names a principal the session no longer records
     * fails as `session_principal_mismatch`, without revoking.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenForAnotherPrincipalThanTheSessionRecordsIsRefused(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        DB::table('authentication_sessions')->update(['principal_id' => IdentifierCoercion::stringify($second->getKey())]);

        $this->assertSwitchFails(FailureReason::SESSION_PRINCIPAL_MISMATCH, $session, $second);

        self::assertNull(DB::table('authentication_sessions')->value('revoked_at'));
    }

    /**
     * The guard's absolute lifetime, counted from the sign-in, bounds the
     * switched session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheGuardsLifetimeBoundsTheSwitchedSession(): void
    {
        [, $second] = $this->seedMemberships();

        $policy = \Mockery::mock(ApplicationPolicy::class);
        $policy->shouldReceive('allowsMethod')->andReturnTrue();
        $policy->shouldReceive('admitIdentifier')->andReturnNull();
        $policy->shouldReceive('lifetimes')
            ->with(self::GUARD)
            ->andReturn(app(JwtTokenServiceFactory::class)->forGuard(self::GUARD)->lifetimes(), new TokenLifetimes(5, 60, 10, 30));

        app()->instance(ApplicationPolicy::class, $policy);

        $session = $this->signIn();
        $signIn  = $this->now;

        $this->advance(60);

        $switched = $this->switched($session, $second);

        self::assertSame($signIn->addMinutes(10)->getTimestamp(), $switched->record->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertSame($signIn->addMinutes(10)->toDateTimeString(), $this->storedTime('absolute_expires_at'));
        self::assertSame($signIn->addMinutes(10)->toDateTimeString(), $this->storedTime('idle_expires_at'));

        $later = $this->signIn();

        $this->advance(599);

        self::assertNotNull(
            $this->sessions(self::GUARD)->switchTo(
                self::bodyToken($later->tokens),
                SwitchTarget::principal($second),
                self::requestClient(),
            )->session,
        );

        $latest = $this->signIn();

        $this->advance(600);

        $this->assertSwitchFails(FailureReason::SESSION_EXPIRED, $latest, $second);
    }

    /**
     * A switch adds no absolute deadline when the guard sets no absolute limit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchAddsNoAbsoluteDeadline(): void
    {
        [, $second] = $this->seedMemberships();

        $this->bindLifetimes(new TokenLifetimes(5, 60, null, 30));

        $session = $this->signIn();

        self::assertNull(DB::table('authentication_sessions')->value('absolute_expires_at'));

        $this->advance(60);

        $switched = $this->switched($session, $second);

        self::assertNull($switched->record->getAbsoluteExpiresAt());
        self::assertNull(DB::table('authentication_sessions')->value('absolute_expires_at'));
        self::assertSame($this->now->addMinutes(60)->toDateTimeString(), $this->storedTime('idle_expires_at'));
    }

    /**
     * A switch of a session with no recorded start keeps its stored deadline.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchOfASessionWithNoRecordedStartKeepsItsStoredDeadline(): void
    {
        [, $second] = $this->seedMemberships();

        $this->bindLifetimes(new TokenLifetimes(5, 60, null, 30));

        $session = $this->signIn();

        Schema::table('authentication_sessions', static function (Blueprint $blueprint): void {
            $blueprint->dateTime('signed_in_at', 0)->nullable()->change();
        });

        DB::table('authentication_sessions')->update(['signed_in_at' => null]);

        $this->advance(60);

        $switched = $this->switched($session, $second);

        self::assertNull($switched->record->getAbsoluteExpiresAt());
        self::assertNull(DB::table('authentication_sessions')->value('absolute_expires_at'));
        self::assertSame($this->now->addMinutes(60)->toDateTimeString(), $this->storedTime('idle_expires_at'));
    }

    /**
     * An absolute limit set since the sign-in lowers the switched session's
     * deadline.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALimitSetSinceTheSignInLowersTheSwitchedSession(): void
    {
        [, $second] = $this->seedMemberships();

        $this->bindLifetimes(new TokenLifetimes(5, 60, null, 30), new TokenLifetimes(5, 60, 10, 30));

        $session = $this->signIn();
        $signIn  = $this->now;

        $this->advance(60);

        $switched = $this->switched($session, $second);

        self::assertSame($signIn->addMinutes(10)->getTimestamp(), $switched->record->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertSame($signIn->addMinutes(10)->toDateTimeString(), $this->storedTime('absolute_expires_at'));
        self::assertSame($signIn->addMinutes(10)->toDateTimeString(), $this->storedTime('idle_expires_at'));
    }

    /**
     * A session past the guard's shortened lifetime fails as `session_expired`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionPastTheGuardsShortenedLifetimeFailsAsExpired(): void
    {
        [, $second] = $this->seedMemberships();

        $policy = \Mockery::mock(ApplicationPolicy::class);
        $policy->shouldReceive('allowsMethod')->andReturnTrue();
        $policy->shouldReceive('admitIdentifier')->andReturnNull();
        $policy->shouldReceive('lifetimes')
            ->with(self::GUARD)
            ->andReturn(app(JwtTokenServiceFactory::class)->forGuard(self::GUARD)->lifetimes(), new TokenLifetimes(5, 60, 10, 30));

        app()->instance(ApplicationPolicy::class, $policy);

        $session = $this->signIn();
        $before  = self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->first());

        $this->advance(600);

        self::assertGreaterThan($this->now->toDateTimeString(), $this->storedTime('absolute_expires_at'));

        $this->assertSwitchFails(FailureReason::SESSION_EXPIRED, $session, $second);

        self::assertSame($before, self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->first()));
    }

    /**
     * Switches are bounded by the refresh limits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSwitchesAreBoundedByTheRefreshLimits(): void
    {
        [, $second] = $this->seedMemberships();

        $session   = $this->signIn();
        $sessionId = IdentifierCoercion::stringify($session->record->getSessionIdentifier());

        $limiter = \Mockery::mock(AttemptLimiter::class);
        $limiter->shouldReceive('blocked')->once()->andReturn(42);

        app()->instance(AttemptLimiter::class, $limiter);

        $this->recordEvents([AuthenticationFailed::class]);

        $blocked = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::principal($second),
            self::requestClient(),
        );

        self::assertSame(FailureReason::RATE_LIMITED, $blocked->reason);
        self::assertSame(42, $blocked->retryAfter);
        self::assertSame(42, $this->recordedEvent(AuthenticationFailed::class)->retryAfter);
        self::assertSame($sessionId, $this->recordedEvent(AuthenticationFailed::class)->context->sessionId);

        $limiter = \Mockery::mock(AttemptLimiter::class);
        $limiter->shouldReceive('blocked')->once()->andReturnNull();
        $limiter->shouldReceive('recordFailure')->once()->with(\Mockery::on(static fn (AttemptSubject $subject): bool => $subject->flow === AttemptFlow::REFRESH
            && $subject->guard                                                                                                          === self::GUARD
            && $subject->identifier                                                                                                     === $sessionId
            && $subject->ip                                                                                                             === self::CLIENT_IP));

        app()->instance(AttemptLimiter::class, $limiter);

        DB::table('authentication_sessions')->update(['revoked_at' => $this->now, 'revoked_reason' => 'revoked']);

        self::assertSame(
            FailureReason::SESSION_REVOKED,
            $this->sessions(self::GUARD)->switchTo(
                self::bodyToken($session->tokens),
                SwitchTarget::principal($second),
                self::requestClient(),
            )->reason,
        );
    }

    /**
     * A switch does not ask the identity-level factor policy.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchDoesNotAskTheIdentityLevelFactorPolicy(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $factors = \Mockery::mock(AdditionalFactorPolicy::class);
        $factors->shouldNotReceive('requirementFor');

        app()->instance(AdditionalFactorPolicy::class, $factors);

        $this->advance(5);

        self::assertSame($second->getKey(), $this->switched($session, $second)->principal->getPrincipalIdentifier());
    }

    /**
     * A tenant-only switch moves the session to another tenant as the same
     * principal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantOnlySwitchMovesTheSessionToAnotherTenant(): void
    {
        [$first, , , $own] = $this->seedMemberships();

        $descendant = $this->below($own);
        $session    = $this->signIn();

        $this->advance(5);

        $this->recordEvents([PrincipalSwitched::class, Login::class]);

        $result = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::tenant(TenantSelection::of(self::modelKey($descendant))),
            self::requestClient(),
        );

        self::assertTrue($result->isSwitched());
        self::assertTrue($result->session?->principal->is($first)); // @phpstan-ignore method.notFound
        self::assertSame([PrincipalSwitched::class], $this->recordedClasses());

        $event = $this->recordedEvent(PrincipalSwitched::class);

        self::assertFalse($event->principalChanged);
        self::assertTrue($event->tenantChanged);
        self::assertSame(IdentifierCoercion::stringify($own->getKey()), $event->previousTenantId);
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), $event->previousPrincipalId);
        EventContextAssertions::assertPrincipal($first, $event->context);
        self::assertSame(IdentifierCoercion::stringify($descendant->getKey()), $event->context->tenantId);

        $record = DB::table('authentication_sessions')->sole();

        self::assertSame(IdentifierCoercion::stringify($descendant->getKey()), $record->tenant_id);
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), IdentifierCoercion::stringify($record->principal_id));
        self::assertSame($this->now->toDateTimeString(), $this->storedTime('switched_at'));
        self::assertSame(IdentifierCoercion::stringify($descendant->getKey()), self::boundTenantId());
        $claims = self::claimsOf($result->session->tokens->accessToken->reveal());

        self::assertSame(IdentifierCoercion::stringify($descendant->getKey()), IdentifierCoercion::stringify($claims['tenant_id'] ?? null));

        $this->assertRefusedAs(FailureReason::SESSION_TENANT_MISMATCH, $session->tokens->accessToken->reveal());

        $this->tenantOf($result->session->tokens->accessToken->reveal())->assertOk()->assertExactJson(['tenant' => IdentifierCoercion::stringify($descendant->getKey())]);
    }

    /**
     * A switch moves the principal and the tenant together.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchMovesThePrincipalAndTheTenantTogether(): void
    {
        [$first, $second, , $own] = $this->seedMemberships();

        $descendant = $this->below(ActivatableTenant::query()->findOrFail($second->tenant_id));
        $session    = $this->signIn();

        $this->advance(5);

        $this->recordEvents([PrincipalSwitched::class]);

        $result = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::principal($second, TenantSelection::of(self::modelKey($descendant))),
            self::requestClient(),
        );

        self::assertTrue($result->session?->principal->is($second)); // @phpstan-ignore method.notFound

        $event = $this->recordedEvent(PrincipalSwitched::class);

        self::assertTrue($event->principalChanged);
        self::assertTrue($event->tenantChanged);
        self::assertSame(IdentifierCoercion::stringify($own->getKey()), $event->previousTenantId);
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), $event->previousPrincipalId);

        $record = DB::table('authentication_sessions')->sole();

        self::assertSame(IdentifierCoercion::stringify($second->getKey()), IdentifierCoercion::stringify($record->principal_id));
        self::assertSame(IdentifierCoercion::stringify($descendant->getKey()), $record->tenant_id);

        $this->assertRefusedAs(FailureReason::SESSION_TENANT_MISMATCH, $session->tokens->accessToken->reveal());
        $this->tenantOf($result->session->tokens->accessToken->reveal())->assertOk()->assertExactJson(['tenant' => IdentifierCoercion::stringify($descendant->getKey())]);
    }

    /**
     * Switching back to a tenant does not restore its old tokens.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSwitchingBackToATenantDoesNotRestoreItsOldTokens(): void
    {
        [, , , $own] = $this->seedMemberships();

        $descendant = $this->below($own);
        $session    = $this->signIn();

        $this->advance(5);

        $away = $this->switchedTo(self::bodyRefreshToken($session->tokens), SwitchTarget::tenant(TenantSelection::of(self::modelKey($descendant))));

        $this->advance(5);

        $back = $this->switchedTo(self::bodyRefreshToken($away->tokens), SwitchTarget::tenant(TenantSelection::principalDefault()));

        self::assertSame(IdentifierCoercion::stringify($own->getKey()), DB::table('authentication_sessions')->value('tenant_id'));
        self::assertSame($this->now->toDateTimeString(), $this->storedTime('switched_at'));

        $this->assertRefusedAs(FailureReason::SESSION_SWITCHED, $session->tokens->accessToken->reveal());
        $this->assertRefusedAs(FailureReason::SESSION_TENANT_MISMATCH, $away->tokens->accessToken->reveal());

        $this->tenantOf($back->tokens->accessToken->reveal())->assertOk()->assertExactJson(['tenant' => IdentifierCoercion::stringify($own->getKey())]);
    }

    /**
     * Two switches in one second refuse every earlier token.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoSwitchesInOneSecondRefuseEveryEarlierToken(): void
    {
        [, , , $own] = $this->seedMemberships();

        $descendant = $this->below($own);
        $session    = $this->signIn();

        $this->advance(5);

        $away = $this->switchedTo(self::bodyRefreshToken($session->tokens), SwitchTarget::tenant(TenantSelection::of(self::modelKey($descendant))));
        $back = $this->switchedTo(self::bodyRefreshToken($away->tokens), SwitchTarget::tenant(TenantSelection::principalDefault()));

        self::assertSame($this->now->addSecond()->toDateTimeString(), $this->storedTime('switched_at'));

        $this->assertRefusedAs(FailureReason::SESSION_SWITCHED, $session->tokens->accessToken->reveal());
        $this->assertRefusedAs(FailureReason::SESSION_TENANT_MISMATCH, $away->tokens->accessToken->reveal());
        $this->assertRefusedAs(FailureReason::SESSION_SWITCHED, $back->tokens->accessToken->reveal());

        $this->advance(1);

        $refreshed = self::sessionsOf($this->freshGuard(self::GUARD))->refresh(
            self::bodyToken($back->tokens),
            self::requestClient(),
        )->session;

        self::assertNotNull($refreshed);

        $this->tenantOf($refreshed->tokens->accessToken->reveal())->assertOk()->assertExactJson(['tenant' => IdentifierCoercion::stringify($own->getKey())]);
    }

    /**
     * A switch to the current tenant and principal rotates the credential like
     * a refresh.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchToTheCurrentTenantRotatesLikeARefresh(): void
    {
        [, , , $own] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        $this->recordEvents([PrincipalSwitched::class]);

        $result = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::tenant(TenantSelection::of(self::modelKey($own))),
            self::requestClient(),
        );

        self::assertTrue($result->isSwitched());
        self::assertSame([], $this->recordedClasses());
        self::assertNull(DB::table('authentication_sessions')->value('switched_at'));
        self::assertSame($this->now->toDateTimeString(), $this->storedTime('refresh_rotated_at'));

        $this->bearer($session->tokens->accessToken->reveal())->assertOk();
    }

    /**
     * A destination tenant the access contracts refuse is refused, the session
     * left as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADestinationTenantTheAccessRefusesIsRefused(): void
    {
        [$first, , , $own] = $this->seedMemberships();

        $other   = ActivatableTenant::query()->create(['name' => 'Unrelated', 'is_active' => true]);
        $session = $this->signIn();
        $row     = self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->sole());

        $foreign = $this->assertTargetFails(FailureReason::TENANT_INELIGIBLE, $session, SwitchTarget::tenant(TenantSelection::of(self::modelKey($other))));

        self::assertSame(IdentifierCoercion::stringify($first->getKey()), $foreign->context->principalId);

        $this->assertTargetFails(FailureReason::TENANT_INELIGIBLE, $session, SwitchTarget::tenant(TenantSelection::none()));

        $descendant = $this->below($own);

        $descendant->forceFill(['is_active' => false])->save();

        $this->assertTargetFails(FailureReason::TENANT_INACTIVE, $session, SwitchTarget::tenant(TenantSelection::of(self::modelKey($descendant))));

        self::assertEquals($row, self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->sole()));
    }

    /**
     * A tenant-only switch is held to the principal the session records.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantOnlySwitchIsHeldToTheRecordedPrincipal(): void
    {
        [$first, , , $own] = $this->seedMemberships();

        $descendant = $this->below($own);
        $session    = $this->signIn();
        $asked      = $this->tree()->asked;
        $resolved   = $this->tree()->resolved;

        $own->forceFill(['is_active' => false])->save();

        $refused = $this->assertTargetFails(FailureReason::TENANT_INACTIVE, $session, SwitchTarget::tenant(TenantSelection::of(self::modelKey($descendant))));

        self::assertSame(IdentifierCoercion::stringify($first->getKey()), $refused->context->principalId);
        self::assertSame($asked, $this->tree()->asked);
        self::assertSame($resolved, $this->tree()->resolved);
    }

    /**
     * A switch keeps the session's proofs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchKeepsTheSessionsProofs(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();
        $proofs  = DB::table('authentication_proofs')->orderBy('id')->get()->all();

        self::assertNotSame([], $proofs);

        $this->advance(60);

        $switched = $this->switched($session, $second);
        $before   = self::claimsOf($session->tokens->accessToken->reveal());
        $after    = self::claimsOf($switched->tokens->accessToken->reveal());

        self::assertEquals($proofs, DB::table('authentication_proofs')->orderBy('id')->get()->all());
        self::assertSame($session->record->getKey(), $switched->record->getKey());
        self::assertSame($before['auth_time'] ?? null, $after['auth_time'] ?? null);
        self::assertSame($before['amr'] ?? null, $after['amr'] ?? null);
    }

    /**
     * A destination requiring its own connections refuses the switch as
     * `sso_required`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADestinationRequiringItsOwnConnectionsRefusesTheSwitch(): void
    {
        [, $second] = $this->seedMemberships();

        $policy = $this->scriptPolicy([IdentifierCoercion::stringify($second->tenant_id) => new TenantRequirement('v1', connections: ['their-idp'])]);

        $session = $this->signIn();
        $row     = self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->sole());

        $this->advance(5);

        $asked   = count($policy->asked);
        $refused = $this->assertSwitchFails(FailureReason::SSO_REQUIRED, $session, $second);

        self::assertSame(IdentifierCoercion::stringify($second->getKey()), $refused->context->principalId);
        self::assertSame(IdentifierCoercion::stringify($second->tenant_id), $refused->context->tenantId);
        self::assertEquals($row, self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->sole()));
        self::assertCount($asked + 1, $policy->asked);

        $this->bearer($session->tokens->accessToken->reveal())->assertOk();
    }

    /**
     * A destination asking for a further factor returns the session to pending
     * until it is met.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADestinationAskingForAFactorReturnsTheSessionToPendingUntilItIsMet(): void
    {
        [, $second, $member] = $this->seedMemberships();

        $this->scriptPolicy([IdentifierCoercion::stringify($second->tenant_id) => new TenantRequirement('v1', new Requirement(multifactor: new RequirementPart))]);

        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $session = $this->signIn();

        $this->advance(5);

        $this->recordEvents([SessionReturnedToPending::class, PrincipalSwitched::class, Authenticated::class]);

        $result = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::principal($second),
            self::requestClient(),
        );

        self::assertTrue($result->isPending());
        self::assertFalse($result->isSwitched());
        self::assertFalse($result->isFailed());
        self::assertNull($result->session);
        self::assertNotNull($result->credential);
        self::assertNotNull($result->pending);
        self::assertSame([PendingRequirement::MFA], $result->pending->requires);
        self::assertSame([RequirementKind::MULTIFACTOR], $result->pending->requirement->kinds());
        self::assertSame($second->getKey(), $result->pending->principal?->getPrincipalIdentifier());
        self::assertSame([SessionReturnedToPending::class], $this->recordedClasses());
        self::assertSame(AuthenticationFlow::SWITCH, $this->recordedEvent(SessionReturnedToPending::class)->flow);

        $record = DB::table('authentication_sessions')->sole();

        self::assertSame('pending', $record->status);
        self::assertSame(IdentifierCoercion::stringify($second->getKey()), IdentifierCoercion::stringify($record->principal_id));
        self::assertSame(IdentifierCoercion::stringify($second->tenant_id), $record->tenant_id);
        self::assertNull($record->revoked_at);

        $this->assertRefusedAs(FailureReason::SESSION_PENDING, $session->tokens->accessToken->reveal());

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertSame(
            FailureReason::SESSION_PENDING,
            self::sessionsOf($this->freshGuard(self::GUARD))->refresh(self::bodyToken($session->tokens), self::requestClient())->reason,
        );
        self::assertNull(DB::table('authentication_sessions')->value('revoked_at'));

        $this->advance(1);

        $this->recordEvents([SessionActivated::class]);

        $active = $this->sessions(self::GUARD)->satisfy(
            $result->credential->reveal(),
            self::adapterProof($member, self::GUARD, $result->pending->id, Purpose::SIGN_IN),
            self::requestClient(),
        );

        self::assertTrue($active->isSignedIn());
        self::assertNotNull($active->session);
        self::assertSame($session->record->getKey(), $active->session->record->getKey());
        self::assertSame(IdentifierCoercion::stringify($second->getKey()), $this->recordedEvent(SessionActivated::class)->context->principalId);
        self::assertSame('active', DB::table('authentication_sessions')->value('status'));
        self::assertSame('v1', DB::table('authentication_sessions')->value('tenant_policy_version'));

        $this->bearer($active->session->tokens->accessToken->reveal())->assertOk()->assertJson(['principal' => $second->getKey()]);
        $this->tenantOf($active->session->tokens->accessToken->reveal())->assertOk()->assertJson(['tenant' => IdentifierCoercion::stringify($second->tenant_id)]);
        $this->assertRefusedAs(FailureReason::SESSION_TENANT_MISMATCH, $session->tokens->accessToken->reveal());
    }

    /**
     * A return to pending names the strictest of the destination's and the
     * identity's requirements.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReturnToPendingNamesTheIdentitysRequirementToo(): void
    {
        [, $second, , $own] = $this->seedMemberships();

        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $session = $this->signIn();

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);

        $this->scriptPolicy([IdentifierCoercion::stringify($second->tenant_id) => new TenantRequirement('v1', new Requirement(multifactor: new RequirementPart))]);

        $this->advance(5);

        $result = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::principal($second),
            self::requestClient(),
        );

        self::assertNotNull($result->credential);
        self::assertSame([RequirementKind::ADDITIONAL_VERIFICATION, RequirementKind::MULTIFACTOR], $result->pending?->requirement->kinds());
        self::assertEquals($result->pending->requirement, $this->sessions(self::GUARD)->pending($result->credential)?->requirement);

        DB::table('authentication_sessions')->delete();

        app()->instance(AdditionalFactorPolicy::class, new NeverRequireAdditionalFactor);

        $retried = $this->signIn();

        $this->advance(5);

        self::assertNotNull(
            self::sessionsOf($this->freshGuard(self::GUARD))->refresh(self::bodyToken($retried->tokens), self::requestClient())->session,
        );

        $this->advance(1);

        app()->instance(AdditionalFactorPolicy::class, new AlwaysRequireAdditionalFactor);

        $this->scriptPolicy([IdentifierCoercion::stringify($own->getKey()) ?? '' => new TenantRequirement('v2', new Requirement(phishingResistance: new RequirementPart))]);

        $returned = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($retried->tokens),
            SwitchTarget::tenant(TenantSelection::principalDefault()),
            self::requestClient(),
        );

        self::assertSame([RequirementKind::ADDITIONAL_VERIFICATION, RequirementKind::PHISHING_RESISTANCE], $returned->pending?->requirement->kinds());
    }

    /**
     * A return to pending forgets the guard's binding to that session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReturnToPendingForgetsTheGuardsBindingToThatSession(): void
    {
        [$first, $second] = $this->seedMemberships();

        $this->scriptPolicy([IdentifierCoercion::stringify($second->tenant_id) => new TenantRequirement('v1', new Requirement(multifactor: new RequirementPart))]);

        $guard   = $this->freshGuard(self::GUARD);
        $service = self::sessionsOf($guard);
        $session = $service->signIn('password', self::credentials('member@example.test'), SignInContext::fromRequest(request(), principal: $first))->session;

        self::assertNotNull($session);
        self::assertSame($session->record, $guard->session());

        $this->advance(5);

        self::assertTrue(
            $service->switchTo(self::bodyToken($session->tokens), SwitchTarget::principal($second), self::requestClient())->isPending(),
        );
        self::assertFalse($guard->hasUser());
        self::assertNull($guard->user());
        self::assertNull($guard->principal());
        self::assertNull($guard->session());
        self::assertNull($guard->tenant());
    }

    /**
     * A switch before the sign-in commits keeps the guard on its destination.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchBeforeTheSignInCommitsKeepsTheGuardOnItsDestination(): void
    {
        [$first, $second] = $this->seedMemberships();

        $guard   = $this->freshGuard(self::GUARD);
        $service = self::sessionsOf($guard);

        DB::beginTransaction();

        $session = $service->signIn('password', self::credentials('member@example.test'), SignInContext::fromRequest(request(), principal: $first))->session;

        self::assertNotNull($session);
        self::assertFalse($guard->hasUser());

        $this->advance(5);

        self::assertTrue(
            $service->switchTo(self::bodyToken($session->tokens), SwitchTarget::principal($second), self::requestClient())->isSwitched(),
        );

        DB::commit();

        self::assertTrue($guard->principal()?->is($second)); // @phpstan-ignore method.notFound
        self::assertSame(IdentifierCoercion::stringify($second->tenant_id), self::boundTenantId());
    }

    /**
     * A tenant switch before the sign-in commits keeps the guard in its
     * destination.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantSwitchBeforeTheSignInCommitsKeepsTheGuardInItsDestination(): void
    {
        [$first] = $this->seedMemberships();

        $this->allowEveryTenant();

        $guard   = $this->freshGuard(self::GUARD);
        $service = self::sessionsOf($guard);

        DB::beginTransaction();

        $session = $service->signIn('password', self::credentials('member@example.test'), SignInContext::fromRequest(request(), principal: $first))->session;

        self::assertNotNull($session);

        $this->advance(5);

        self::assertTrue(
            $service->switchTo(
                self::bodyToken($session->tokens),
                SwitchTarget::tenant(TenantSelection::none()),
                self::requestClient(),
            )->isSwitched(),
        );

        DB::commit();

        self::assertTrue($guard->principal()?->is($first)); // @phpstan-ignore method.notFound
        self::assertNull(self::boundTenantId());
    }

    /**
     * A destination whose factor the session meets switches and records the
     * policy version.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADestinationWhoseFactorTheSessionMeetsSwitchesAndRecordsTheVersion(): void
    {
        [, $second] = $this->seedMemberships();

        $this->scriptPolicy([IdentifierCoercion::stringify($second->tenant_id) => new TenantRequirement('v7', new Requirement(multifactor: new RequirementPart))]);

        $session = $this->signIn();

        $check = \Mockery::mock(RequirementCheck::class);
        $check->shouldReceive('evaluate')->once()->andReturn(new RequirementEvaluation([]));

        app()->instance(RequirementCheck::class, $check);

        $this->advance(5);

        self::assertSame($second->getKey(), $this->switched($session, $second)->principal->getPrincipalIdentifier());
        self::assertSame('v7', DB::table('authentication_sessions')->value('tenant_policy_version'));
    }

    /**
     * A tenant-only switch is held to the destination tenant's policy.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATenantOnlySwitchIsHeldToTheDestinationsPolicy(): void
    {
        [, , , $own] = $this->seedMemberships();

        $descendant = $this->below($own);

        $this->scriptPolicy([IdentifierCoercion::stringify($descendant->getKey()) => new TenantRequirement(connections: [])]);

        $session = $this->signIn();

        $this->advance(5);

        $this->assertTargetFails(FailureReason::SSO_REQUIRED, $session, SwitchTarget::tenant(TenantSelection::of(self::modelKey($descendant))));

        self::assertSame(IdentifierCoercion::stringify($own->getKey()), DB::table('authentication_sessions')->value('tenant_id'));
    }

    /**
     * A lost response to a switch that moved the floor is answered again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALostResponseToASwitchThatMovedTheFloorIsAnsweredAgain(): void
    {
        [$first, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        $away = $this->switched($session, $second);
        $back = $this->switchedTo(self::bodyRefreshToken($away->tokens), SwitchTarget::principal($first));

        self::assertNotSame($this->storedTime('refresh_rotated_at'), $this->storedTime('switched_at'));
        self::assertIsModel($first, $back->principal);

        $row = self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->sole());

        $this->recordEvents([PrincipalSwitched::class, AuthenticationFailed::class]);

        $retried = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($away->tokens),
            SwitchTarget::principal($first),
            self::requestClient(),
        );

        self::assertTrue($retried->isSwitched());
        self::assertIsModel($first, $retried->session?->principal);
        self::assertSame([], $this->recordedClasses());
        self::assertEquals($row, self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->sole()));
    }

    /**
     * A grace retry is held to the tenant's authentication policy again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGraceRetryIsHeldToTheTenantsPolicyAgain(): void
    {
        [, , , $own] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        self::assertNotNull(
            self::sessionsOf($this->freshGuard(self::GUARD))->refresh(self::bodyToken($session->tokens), self::requestClient())->session,
        );

        $this->advance(1);

        $tenant = IdentifierCoercion::stringify($own->getKey()) ?? '';
        $target = SwitchTarget::tenant(TenantSelection::principalDefault());

        $this->scriptPolicy([$tenant => new TenantRequirement('v1', connections: ['conn-a'])]);

        $row = self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->sole());

        $this->assertTargetFails(FailureReason::SSO_REQUIRED, $session, $target);

        self::assertEquals($row, self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->sole()));

        $this->scriptPolicy([$tenant => new TenantRequirement('v2', new Requirement(phishingResistance: new RequirementPart))]);

        $this->recordEvents([SessionReturnedToPending::class, PrincipalSwitched::class]);

        $returned = $this->sessions(self::GUARD)->switchTo(self::bodyToken($session->tokens), $target, self::requestClient());

        self::assertTrue($returned->isPending());
        self::assertSame([RequirementKind::PHISHING_RESISTANCE], $returned->pending?->requirement->kinds());
        self::assertNull($returned->session);
        self::assertNotNull($returned->credential);
        self::assertSame([SessionReturnedToPending::class], $this->recordedClasses());
        self::assertSame(AuthenticationFlow::SWITCH, $this->recordedEvent(SessionReturnedToPending::class)->flow);
        self::assertSame('pending', DB::table('authentication_sessions')->value('status'));
    }

    /**
     * A switch whose bind listener throws is still reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchWhoseBindListenerThrowsIsStillReported(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();
        $before  = (array) DB::table('authentication_sessions')->sole();

        Event::listen(PrincipalAssigned::class, static function (): never {
            throw new \RuntimeException('listener failed');
        });

        $this->recordEvents([PrincipalSwitched::class]);

        $guard = $this->freshGuard(self::GUARD);

        DB::beginTransaction();

        self::assertTrue(
            self::sessionsOf($guard)->switchTo(
                self::bodyToken($session->tokens),
                SwitchTarget::principal($second),
                self::requestClient(),
            )->isSwitched(),
        );
        self::assertSame([], $this->recordedClasses());

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertFalse($guard->hasUser());
        self::assertEquals($before, (array) DB::table('authentication_sessions')->sole());

        self::assertSame('listener failed', $this->failedSwitch(self::bodyRefreshToken($session->tokens), $second));
        self::assertSame([PrincipalSwitched::class], $this->recordedClasses());
        self::assertSame(IdentifierCoercion::stringify($second->getKey()), IdentifierCoercion::stringify(DB::table('authentication_sessions')->value('principal_id')));
    }

    /**
     * A switch whose bind listener throws is reported on the caller's commit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchWhoseBindListenerThrowsIsReportedOnTheCallersCommit(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        Event::listen(PrincipalAssigned::class, static function (): never {
            throw new \RuntimeException('listener failed');
        });

        $this->recordEvents([PrincipalSwitched::class]);

        DB::beginTransaction();

        self::assertTrue(
            $this->sessions(self::GUARD)->switchTo(
                self::bodyToken($session->tokens),
                SwitchTarget::principal($second),
                self::requestClient(),
            )->isSwitched(),
        );
        self::assertSame([], $this->recordedClasses());

        try {
            DB::commit();
            self::fail('Expected the bind listener to throw from the commit.');
        } catch (\RuntimeException $exception) {
            self::assertSame('listener failed', $exception->getMessage());
        }

        self::assertSame([PrincipalSwitched::class], $this->recordedClasses());
        self::assertSame(IdentifierCoercion::stringify($second->getKey()), IdentifierCoercion::stringify(DB::table('authentication_sessions')->value('principal_id')));
    }

    /**
     * A cookie application switches from plain values, described by the client
     * given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACookieApplicationSwitchesFromPlainValues(): void
    {
        config()->set('authentication.session.last_used_throttle_seconds', 0);

        [$first, $second] = $this->seedMemberships();

        $session = $this->signInWithCookie();
        $client  = self::sameSiteClient();

        $this->advance(5);

        $guard = $this->crossSiteGuard(self::BROWSER);

        $this->recordEvents([Attempting::class, Failed::class, AuthenticationFailed::class, PrincipalSwitched::class, PrincipalAssigned::class, SessionAuthenticated::class]);

        $result = self::sessionsOf($guard)->switchTo(self::presentedToken(self::cookieTokenOf($session), RefreshTokenSource::COOKIE), SwitchTarget::principal($second), $client);

        self::assertNotNull($result);
        self::assertTrue($result->isSwitched());
        self::assertSame(RefreshTokenSource::COOKIE, $result->source);

        $switched = $result->session;

        self::assertNotNull($switched);
        self::assertNull($switched->tokens->refreshToken);
        self::assertSame(['__Host-' . self::BROWSER . '_refresh_token', '/'], [$switched->tokens->refreshCookie?->name, $switched->tokens->refreshCookie?->path]);
        self::assertEqualsCanonicalizing([PrincipalSwitched::class, PrincipalAssigned::class, SessionAuthenticated::class], $this->recordedClasses());
        self::assertSame($client, $this->recordedEvent(PrincipalSwitched::class)->context->client);
        self::assertSame($client, $this->recordedEvent(PrincipalAssigned::class)->context->client);
        self::assertSame($client, $this->recordedEvent(SessionAuthenticated::class)->context->client);
        self::assertSame($second->getKey(), $guard->principal()?->getPrincipalIdentifier());

        $record = DB::table('authentication_sessions')->sole();

        self::assertSame([self::PLAIN_IP, self::PLAIN_AGENT], [$record->last_used_ip, $record->last_used_user_agent]);

        $this->advance(5);

        $again = self::presentedToken(self::cookieTokenOf($switched), RefreshTokenSource::COOKIE);

        self::assertTrue($this->sessions(self::BROWSER)->switchTo($again, SwitchTarget::principal($first), $client)->isSwitched());
    }

    /**
     * Rows of `[presented, client, reason, source]` a cookie application's
     * plain switch refuses.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(string): (\SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken), 1: \SineMacula\Laravel\Authentication\Http\ClientContext, 2: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason, 3: ?\SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideRefusedPlainSwitches(): iterable
    {
        $cookie = RefreshTokenSource::COOKIE;

        yield 'the cookie from a cross-site client' => [static fn (string $token): PresentedRefreshToken => self::presentedToken(
            $token,
            $cookie,
        ), self::crossSiteClient(), FailureReason::CROSS_SITE_REQUEST, $cookie];
        yield 'the cookie twice' => [static fn (string $token): PresentedRefreshToken => self::presentedToken(
            $token,
            $cookie,
            [$cookie, $cookie],
        ), self::sameSiteClient(), FailureReason::REFRESH_TOKEN_CONFLICT, $cookie];
        yield 'the cookie and the body' => [static fn (string $token): PresentedRefreshToken => self::presentedToken(
            $token,
            $cookie,
            [$cookie, RefreshTokenSource::BODY],
        ), self::sameSiteClient(), FailureReason::REFRESH_TOKEN_CONFLICT, $cookie];
        yield 'a token from the body' => [static fn (string $token): PresentedRefreshToken => PresentedRefreshToken::fromBody(
            $token,
        ), self::sameSiteClient(), FailureReason::REFRESH_TRANSPORT_MISMATCH, RefreshTokenSource::BODY];
        yield 'a conflict handed in' => [static fn (): FailureReason => FailureReason::REFRESH_TOKEN_CONFLICT, self::sameSiteClient(), FailureReason::REFRESH_TOKEN_CONFLICT, null];
        yield 'an invalid token handed in' => [static fn (): FailureReason => FailureReason::TOKEN_INVALID, self::sameSiteClient(), FailureReason::TOKEN_INVALID, null];
    }

    /**
     * A cookie application's plain switch is refused before any session is
     * read.
     *
     * @param  \Closure(string): (\SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken)  $presented
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?\SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRefusedPlainSwitches')]
    public function testACookieApplicationsPlainSwitchIsJudgedBeforeTheSession(\Closure $presented, ClientContext $client, FailureReason $reason, ?RefreshTokenSource $source): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signInWithCookie();
        $token   = self::cookieTokenOf($session);
        $before  = (array) DB::table('authentication_sessions')->sole();

        app()->instance('request', Request::create('/auth/switch', 'POST', [], ['__Host-' . self::BROWSER . '_refresh_token' => $token], [], [
            'HTTP_ORIGIN'           => 'http://localhost',
            'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest',
        ]));

        Auth::forgetGuards();

        $this->recordEvents([Attempting::class, Failed::class, AuthenticationFailed::class]);

        $result = Auth::sessions(self::BROWSER)->switchTo($presented($token), SwitchTarget::principal($second), $client);

        self::assertNotNull($result);
        self::assertSame([$reason, null, $source], [$result->reason, $result->retryAfter, $result->source]);
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame([AuthenticationFlow::SWITCH, $reason, self::BROWSER], [$failure->flow, $failure->reason, $failure->context->guard]);
        self::assertSame($client, $failure->context->client);
        self::assertEquals($before, (array) DB::table('authentication_sessions')->sole());
    }

    /**
     * A plain switch of nothing does nothing, and a foreign reason handed in
     * throws.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlainSwitchOfNothingOrOfAForeignReason(): void
    {
        [, $second] = $this->seedMemberships();

        $this->recordEvents([Attempting::class, Failed::class, AuthenticationFailed::class, PrincipalSwitched::class]);

        foreach ([self::BROWSER, self::GUARD] as $guard) {

            self::assertNull($this->sessions($guard)->switchTo(null, SwitchTarget::principal($second), self::sameSiteClient()));

            foreach ([FailureReason::CROSS_SITE_REQUEST, FailureReason::RATE_LIMITED, FailureReason::ROTATION_REUSE] as $reason) {
                try {
                    $this->sessions($guard)->switchTo($reason, SwitchTarget::principal($second), self::sameSiteClient());

                    self::fail("A switch took {$reason->value} as what the transport extracted.");
                } catch (\InvalidArgumentException $exception) {
                    self::assertStringContainsString("`{$reason->value}`", $exception->getMessage());
                }
            }
        }

        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A plain switch replay is reported with the client given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlainSwitchReplayIsReportedWithTheClientGiven(): void
    {
        [$first, $second] = $this->seedMemberships();

        $session = $this->signInWithCookie();
        $old     = self::presentedToken(self::cookieTokenOf($session), RefreshTokenSource::COOKIE);
        $client  = self::sameSiteClient();

        $this->advance(5);

        self::assertTrue($this->sessions(self::BROWSER)->switchTo($old, SwitchTarget::principal($second), $client)->isSwitched());

        $this->advance(31);

        $guard = $this->crossSiteGuard(self::BROWSER);

        $this->recordEvents([AuthenticationFailed::class, SessionRevoked::class]);

        $result = self::sessionsOf($guard)->switchTo($old, SwitchTarget::principal($first), $client);

        self::assertSame([FailureReason::ROTATION_REUSE, RefreshTokenSource::COOKIE], [$result->reason, $result->source]);
        self::assertSame([SessionRevoked::class, AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame($client, $this->recordedEvent(SessionRevoked::class)->context->client);
        self::assertSame($client, $this->recordedEvent(AuthenticationFailed::class)->context->client);
        self::assertSame('rotation_reuse', DB::table('authentication_sessions')->value('revoked_reason'));
    }

    /**
     * A plain switch returned to pending is reported with the client given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlainSwitchReturnedToPendingIsReportedWithTheClientGiven(): void
    {
        [, $second] = $this->seedMemberships();

        $this->scriptPolicy([IdentifierCoercion::stringify($second->tenant_id) => new TenantRequirement('v1', new Requirement(multifactor: new RequirementPart))]);

        app()->instance(RequirementCheck::class, new ProofJudgingRequirementCheck);

        $session = $this->signInWithCookie();
        $client  = self::sameSiteClient();

        $this->advance(5);

        $guard = $this->crossSiteGuard(self::BROWSER);

        $this->recordEvents([SessionReturnedToPending::class, PrincipalAssigned::class]);

        $result = self::sessionsOf($guard)->switchTo(self::presentedToken(self::cookieTokenOf($session), RefreshTokenSource::COOKIE), SwitchTarget::principal($second), $client);

        self::assertTrue($result->isPending());
        self::assertNotNull($result->credential);
        self::assertSame([SessionReturnedToPending::class], $this->recordedClasses());
        self::assertSame($client, $this->recordedEvent(SessionReturnedToPending::class)->context->client);
        self::assertSame(AuthenticationFlow::SWITCH, $this->recordedEvent(SessionReturnedToPending::class)->flow);
        self::assertFalse($guard->hasUser());
    }

    /**
     * A plain switch is limited by the client's IP address, not the guard's
     * request's, and by the token's session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlainSwitchIsLimitedByTheClientsAddress(): void
    {
        [, $second] = $this->seedMemberships();

        $session   = $this->signInWithCookie();
        $sessionId = IdentifierCoercion::stringify($session->record->getSessionIdentifier());
        $client    = self::sameSiteClient();
        $limiter   = \Mockery::mock(AttemptLimiter::class);

        $limiter->shouldReceive('blocked')
            ->once()
            ->with(
                \Mockery::on(
                    static fn (AttemptSubject $subject): bool => $subject->flow === AttemptFlow::REFRESH && $subject->ip === self::PLAIN_IP && $subject->identifier === $sessionId,
                ),
            )
            ->andReturn(42);

        app()->instance(AttemptLimiter::class, $limiter);

        $this->recordEvents([AuthenticationFailed::class]);

        $result = self::sessionsOf($this->crossSiteGuard(self::BROWSER))->switchTo(
            self::presentedToken(self::cookieTokenOf($session), RefreshTokenSource::COOKIE),
            SwitchTarget::principal($second),
            $client,
        );

        self::assertSame([FailureReason::RATE_LIMITED, 42], [$result->reason, $result->retryAfter]);
        self::assertSame($client, $this->recordedEvent(AuthenticationFailed::class)->context->client);
    }

    /**
     * A plain switch waits for the caller's commit.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPlainSwitchWaitsForTheCallersCommit(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signInWithCookie();
        $token   = self::presentedToken(self::cookieTokenOf($session), RefreshTokenSource::COOKIE);
        $client  = self::sameSiteClient();
        $before  = (array) DB::table('authentication_sessions')->sole();

        $this->advance(5);

        $guard = $this->crossSiteGuard(self::BROWSER);

        $this->recordEvents([PrincipalSwitched::class, PrincipalAssigned::class]);

        DB::beginTransaction();

        self::assertTrue(self::sessionsOf($guard)->switchTo($token, SwitchTarget::principal($second), $client)->isSwitched());

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertFalse($guard->hasUser());
        self::assertEquals($before, (array) DB::table('authentication_sessions')->sole());

        DB::transaction(function () use ($guard, $token, $second, $client): void {
            self::assertTrue(self::sessionsOf($guard)->switchTo($token, SwitchTarget::principal($second), $client)->isSwitched());
            self::assertSame([], $this->recordedClasses());
        });

        self::assertEqualsCanonicalizing([PrincipalSwitched::class, PrincipalAssigned::class], $this->recordedClasses());
        self::assertSame($client, $this->recordedEvent(PrincipalAssigned::class)->context->client);
        self::assertSame($second->getKey(), $guard->principal()?->getPrincipalIdentifier());
    }

    /**
     * A switch expecting its own session, or none, is made.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchExpectingItsOwnSessionIsMade(): void
    {
        [$first, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        $switched = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::principal($second),
            self::requestClient(),
            expectedSession: IdentifierCoercion::stringify($session->record->getSessionIdentifier()),
        );

        self::assertTrue($switched->isSwitched());

        $this->advance(5);

        self::assertTrue(
            $this->sessions(self::GUARD)->switchTo(
                self::bodyToken($switched->session?->tokens),
                SwitchTarget::principal($first),
                self::requestClient(),
                expectedSession: null,
            )->isSwitched(),
        );
    }

    /**
     * A switch proving another session than expected is refused as
     * `session_mismatch`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchProvingAnotherSessionThanExpectedIsRefused(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();
        $other   = $this->signIn();
        $id      = IdentifierCoercion::stringify($session->record->getSessionIdentifier());
        $before  = self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->where('id', $id)->sole());

        $this->advance(5);

        $limiter = \Mockery::mock(AttemptLimiter::class);
        $limiter->shouldReceive('blocked')->once()->andReturnNull();
        $limiter->shouldReceive('recordFailure')->once()->with(\Mockery::on(static fn (AttemptSubject $subject): bool => $subject->flow === AttemptFlow::REFRESH
            && $subject->guard                                                                                                          === self::GUARD
            && $subject->identifier                                                                                                     === $id
            && $subject->ip                                                                                                             === self::CLIENT_IP));

        app()->instance(AttemptLimiter::class, $limiter);

        $this->recordEvents([AuthenticationFailed::class, PrincipalSwitched::class, SessionRevoked::class, PrincipalAssigned::class]);

        $result = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::principal($second),
            self::requestClient(),
            expectedSession: self::modelKey($other->record),
        );

        self::assertSame(FailureReason::SESSION_MISMATCH, $result->reason);
        self::assertNull($result->session);
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());

        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(AuthenticationFlow::SWITCH, $failed->flow);
        self::assertSame(FailureReason::SESSION_MISMATCH, $failed->reason);
        self::assertSame(self::GUARD, $failed->context->guard);
        self::assertSame('password', $failed->context->method);
        EventContextAssertions::assertSession($session->record, $failed->context);
        self::assertEquals($before, self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->where('id', $id)->sole()));
        self::assertTrue(Auth::guard(self::GUARD)->guest());
    }

    /**
     * A switch expecting an integer that is not the session's id is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchExpectingAnIntegerThatIsNotTheSessionIdIsRefused(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        foreach ([42, 0, '', '0'] as $expected) {

            $result = $this->sessions(self::GUARD)->switchTo(
                self::bodyToken($session->tokens),
                SwitchTarget::principal($second),
                self::requestClient(),
                expectedSession: $expected,
            );

            self::assertSame(FailureReason::SESSION_MISMATCH, $result->reason);
        }
    }

    /**
     * A grace retry is held to the expected session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGraceRetryIsHeldToTheExpectedSession(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();
        $other   = $this->signIn();
        $id      = self::modelKey($session->record);

        $this->advance(5);
        $this->switched($session, $second);
        $this->advance(5);

        $row = self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->where('id', $id)->sole());

        $retry = fn (int|string $expected) => $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::principal($second),
            self::requestClient(),
            expectedSession: $expected,
        );

        self::assertSame(FailureReason::SESSION_MISMATCH, $retry(self::modelKey($other->record))->reason);
        self::assertEquals($row, self::withoutIssuanceGuard((array) DB::table('authentication_sessions')->where('id', $id)->sole()));
        self::assertNull(DB::table('authentication_sessions')->where('id', $id)->value('revoked_at'));
        self::assertTrue($retry($id)->isSwitched());
    }

    /**
     * A replay expecting another session still revokes as `rotation_reuse`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReplayExpectingAnotherSessionStillRevokesAsReuse(): void
    {
        [$first, $second] = $this->seedMemberships();

        $session = $this->signIn();
        $other   = $this->signIn();

        $this->advance(5);
        $this->switched($session, $second);
        $this->advance(31);

        $this->recordEvents([AuthenticationFailed::class, SessionRevoked::class]);

        $result = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::principal($first),
            self::requestClient(),
            expectedSession: self::modelKey($other->record),
        );

        self::assertSame(FailureReason::ROTATION_REUSE, $result->reason);
        self::assertSame([SessionRevoked::class, AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(FailureReason::ROTATION_REUSE, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertSame('rotation_reuse', DB::table('authentication_sessions')->where('id', $session->record->getSessionIdentifier())->value('revoked_reason'));
        self::assertNull(DB::table('authentication_sessions')->where('id', $other->record->getSessionIdentifier())->value('revoked_at'));
    }

    /**
     * A session the token's own checks refuse reports its own reason, not the
     * mismatch, whatever session was expected.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevokedSessionExpectingAnotherReportsItsOwnReason(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();
        $other   = $this->signIn();

        DB::table('authentication_sessions')->where('id', $session->record->getSessionIdentifier())->update(['revoked_at' => $this->now, 'revoked_reason' => 'revoked']);

        $result = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::principal($second),
            self::requestClient(),
            expectedSession: self::modelKey($other->record),
        );

        self::assertSame(FailureReason::SESSION_REVOKED, $result->reason);
    }

    /**
     * Register the guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('auth.guards.' . self::BROWSER, [
            'driver'        => 'jwt',
            'provider'      => 'members',
            'application'   => ['methods' => ['password']],
            'refresh_token' => ['transport' => 'cookie', 'cookie' => ['path' => '/']],
        ]);
    }

    /**
     * Sign the member in as its default membership on the cookie application,
     * from a page of its own site.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signInWithCookie(): SignedInSession
    {
        $member   = ActivatableTenantMember::query()->where('email', 'member@example.test')->firstOrFail();
        $sessions = $this->sessions(self::BROWSER);
        $context  = SignInContext::fromRequest(request(), principal: $member->resolveDefaultPrincipal());
        $session  = $sessions->signIn('password', self::credentials('member@example.test'), $context)->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Switch to the membership named with the request's refresh token, as a
     * controller does.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array<string, ?string>
     *
     * @throws \Throwable
     */
    private static function switchRoute(Request $request): array
    {
        $target = SwitchTarget::principal(ActivatableTenantMembership::query()->findOrFail($request->integer('membership')));
        $result = Auth::sessions(self::GUARD)->switchTo(Auth::refreshTransport(self::GUARD)->extract($request), $target, ClientContext::fromRequest($request));

        return [
            'outcome' => $result === null ? 'none' : ($result->isSwitched() ? 'switched' : 'failed'),
            'reason'  => $result?->reason?->value,
            'source'  => $result?->source?->value,
            'refresh' => $result?->session?->tokens->refreshToken?->reveal(),
        ];
    }

    /**
     * Persist a member with a membership in an active tenant (its default
     * principal) and a second one in another active tenant.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{0: \Tests\Integration\Fixtures\ActivatableTenantMembership, 1: \Tests\Integration\Fixtures\ActivatableTenantMembership, 2: \Tests\Integration\Fixtures\ActivatableTenantMember, 3: \Tests\Integration\Fixtures\ActivatableTenant}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function seedMemberships(): array
    {
        [$member, $first, $tenant] = $this->seedMember();

        $other  = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $second = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);

        return [$first, $second, $member, $tenant];
    }

    /**
     * Sign the member in as its default membership, so it is not held pending
     * for a choice.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(): SignedInSession
    {
        $member  = ActivatableTenantMember::query()->where('email', 'member@example.test')->firstOrFail();
        $context = SignInContext::fromRequest(request(), principal: $member->resolveDefaultPrincipal());
        $session = $this->sessions(self::GUARD)->signIn('password', self::credentials('member@example.test'), $context)->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Switch the session to the target through the session service.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @param  \Tests\Integration\Fixtures\ActivatableTenantMembership  $target
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function switched(SignedInSession $session, ActivatableTenantMembership $target): SignedInSession
    {
        $switched = $this->sessions(self::GUARD)->switchTo(
            self::bodyToken($session->tokens),
            SwitchTarget::principal($target),
            self::requestClient(),
        )->session;

        self::assertNotNull($switched);

        return $switched;
    }

    /**
     * Assert a switch of the session to the target fails for the reason,
     * reported as a `switch` failure, and return that report.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $target
     * @param  ?string  $token
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     *
     * @throws \Throwable
     */
    private function assertSwitchFails(FailureReason $reason, SignedInSession $session, Principal $target, ?string $token = null): AuthenticationFailed
    {
        $this->recordEvents([AuthenticationFailed::class]);

        $result = $this->sessions(self::GUARD)->switchTo(
            $token === null ? self::bodyToken($session->tokens) : PresentedRefreshToken::fromBody($token),
            SwitchTarget::principal($target),
            self::requestClient(),
        );

        self::assertTrue($result->isFailed());
        self::assertFalse($result->isSwitched());
        self::assertNull($result->session);
        self::assertSame($reason, $result->reason);
        self::assertSame(AuthenticationFlow::SWITCH, $this->recordedEvent(AuthenticationFailed::class)->flow);
        self::assertSame($reason, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertTrue(Auth::guard(self::GUARD)->guest());

        return $this->recordedEvent(AuthenticationFailed::class);
    }

    /**
     * The claims of a token, read without checking it.
     *
     * @param  string  $token
     * @return array<string, mixed>
     */
    private static function claimsOf(string $token): array
    {
        $claims = json_decode(JWT::urlsafeB64Decode(explode('.', $token)[1]), true);

        self::assertIsArray($claims);

        /** @var array<string, mixed> $claims */
        return $claims;
    }

    /**
     * The expiry a token carries.
     *
     * @param  string  $token
     * @return int
     */
    private static function expiryOf(string $token): int
    {
        $expiry = self::claimsOf($token)['exp'] ?? null;

        self::assertIsInt($expiry);

        return $expiry;
    }

    /**
     * Bind a tenant access that lets any principal act in any tenant, or in
     * none.
     *
     * @return void
     */
    private function allowEveryTenant(): void
    {
        app()->instance(TenantAccess::class, new readonly class implements TenantAccess {
            /**
             * Let any principal act in any tenant, or in none.
             *
             * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
             * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
             * @return bool
             */
            #[\Override]
            public function mayActIn(Principal $principal, ?Tenant $tenant): bool
            {
                return true;
            }
        });
    }

    /**
     * Bind an application policy that allows and admits everything and gives
     * the guard the lifetimes, in turn, the last one from then on.
     *
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  $first
     * @param  \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes  ...$then
     * @return void
     */
    private function bindLifetimes(TokenLifetimes $first, TokenLifetimes ...$then): void
    {
        $policy = \Mockery::mock(ApplicationPolicy::class);
        $policy->shouldReceive('allowsMethod')->andReturnTrue();
        $policy->shouldReceive('admitIdentifier')->andReturnNull();
        $policy->shouldReceive('lifetimes')->with(self::GUARD)->andReturn($first, ...$then);

        app()->instance(ApplicationPolicy::class, $policy);
    }

    /**
     * The stored time in the one session row's column, to the second.
     *
     * @param  string  $column
     * @return string
     */
    private function storedTime(string $column): string
    {
        $value = DB::table('authentication_sessions')->value($column);

        self::assertIsString($value);

        return CarbonImmutable::parse($value)->toDateTimeString();
    }

    /**
     * Post a switch of the refresh token's session to the target.
     *
     * @param  string  $refreshToken
     * @param  \Tests\Integration\Fixtures\ActivatableTenantMembership  $target
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function switch(string $refreshToken, ActivatableTenantMembership $target): TestResponse
    {
        Auth::forgetGuards();

        return $this->postJson('/switch', ['refresh' => $refreshToken, 'membership' => $target->getKey()]);
    }

    /**
     * Switch the session the refresh token proves to the principal through the
     * session service, expecting a listener to throw, and return its message.
     *
     * @param  string  $refreshToken
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return string
     *
     * @throws \Throwable
     */
    private function failedSwitch(#[\SensitiveParameter] string $refreshToken, Principal $principal): string
    {
        try {
            $this->sessions(self::GUARD)->switchTo(PresentedRefreshToken::fromBody($refreshToken), SwitchTarget::principal($principal), self::requestClient());
        } catch (\RuntimeException $exception) {
            return $exception->getMessage();
        }

        self::fail('Expected the listener to throw.');
    }

    /**
     * The token the response's JSON holds under the key, failing the test when
     * it holds none.
     *
     * @param  \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>  $response
     * @param  string  $key
     * @return string
     */
    private static function tokenIn(TestResponse $response, string $key): string
    {
        $token = $response->json($key);

        self::assertIsString($token, "The response holds no {$key} token.");

        return $token;
    }

    /**
     * Ask who the access token acts as.
     *
     * @param  string  $accessToken
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(string $accessToken): TestResponse
    {
        Auth::forgetGuards();

        return $this->withHeaders(['Authorization' => 'Bearer ' . $accessToken])->getJson('/me');
    }

    /**
     * Move the clocks the given number of seconds on.
     *
     * @param  int  $seconds
     * @return void
     */
    private function advance(int $seconds): void
    {
        $this->freezeAt($this->now->addSeconds($seconds));
    }

    /**
     * Freeze every clock at the time.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    private function freezeAt(CarbonImmutable $time): void
    {
        $this->now = $time;

        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }

    /**
     * Bind the application's tree as the tenant access and resolver, once, and
     * return it.
     *
     * @return \Tests\Fixtures\Tenancy\DescendantTenants
     */
    private function tree(): DescendantTenants
    {
        if ($this->tree === null) {

            $this->tree = new DescendantTenants;

            app()->instance(TenantAccess::class, $this->tree);
            app()->instance(TenantResolver::class, $this->tree);
        }

        return $this->tree;
    }

    /**
     * Create an active tenant the application's tree lists below the tenant.
     *
     * @param  \Tests\Integration\Fixtures\ActivatableTenant  $tenant
     * @return \Tests\Integration\Fixtures\ActivatableTenant
     */
    private function below(ActivatableTenant $tenant): ActivatableTenant
    {
        $descendant = ActivatableTenant::query()->create(['name' => 'Descendant', 'is_active' => true]);

        $this->tree()->place(self::modelKey($descendant), self::modelKey($tenant));

        return $descendant;
    }

    /**
     * Switch the refresh token's session to the target through the session
     * service, which must succeed.
     *
     * @param  string  $refreshToken
     * @param  \SineMacula\Laravel\Authentication\Sessions\SwitchTarget  $target
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function switchedTo(string $refreshToken, SwitchTarget $target): SignedInSession
    {
        $switched = $this->sessions(self::GUARD)->switchTo(PresentedRefreshToken::fromBody($refreshToken), $target, self::requestClient())->session;

        self::assertNotNull($switched);

        return $switched;
    }

    /**
     * Assert a switch of the session to the target fails for the reason,
     * reported as a `switch` failure, and return that report.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @param  \SineMacula\Laravel\Authentication\Sessions\SwitchTarget  $target
     * @return \SineMacula\Laravel\Authentication\Events\AuthenticationFailed
     *
     * @throws \Throwable
     */
    private function assertTargetFails(FailureReason $reason, SignedInSession $session, SwitchTarget $target): AuthenticationFailed
    {
        $this->recordEvents([AuthenticationFailed::class]);

        $result = $this->sessions(self::GUARD)->switchTo(self::bodyToken($session->tokens), $target, self::requestClient());

        self::assertTrue($result->isFailed());
        self::assertSame($reason, $result->reason);
        self::assertSame(AuthenticationFlow::SWITCH, $this->recordedEvent(AuthenticationFailed::class)->flow);
        self::assertSame($reason, $this->recordedEvent(AuthenticationFailed::class)->reason);

        return $this->recordedEvent(AuthenticationFailed::class);
    }

    /**
     * Assert the access token is refused for the reason.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  string  $accessToken
     * @return void
     */
    private function assertRefusedAs(FailureReason $reason, string $accessToken): void
    {
        $this->recordEvents([AuthenticationFailed::class]);

        $this->bearer($accessToken)->assertUnauthorized();

        self::assertSame($reason, $this->recordedEvent(AuthenticationFailed::class)->reason);
    }

    /**
     * Ask which tenant the access token acts in.
     *
     * @param  string  $accessToken
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function tenantOf(string $accessToken): TestResponse
    {
        Auth::forgetGuards();

        return $this->withHeaders(['Authorization' => 'Bearer ' . $accessToken])->getJson('/tenant');
    }

    /**
     * The identifier of the tenant the guard is bound to act in.
     *
     * @return ?string
     */
    private static function boundTenantId(): ?string
    {
        $guard = app('auth')->guard(self::GUARD);

        assert($guard instanceof JwtGuard);

        return IdentifierCoercion::stringify($guard->tenant()?->getTenantIdentifier());
    }

    /**
     * Bind an application access that keeps the principals of the tenant out of
     * every application.
     *
     * @param  mixed  $tenantId
     * @return void
     */
    private static function refuseTenantsPrincipals(mixed $tenantId): void
    {
        app()->instance(ApplicationAccess::class, new RefusingApplicationAccess(
            static fn (string $guard, Principal $principal): bool => IdentifierCoercion::matches($principal->getTenant()?->getTenantIdentifier(), $tenantId),
        ));
    }

    /**
     * Bind and return a tenant authentication policy that answers each tenant
     * with its requirement.
     *
     * @param  array<array-key, \SineMacula\Laravel\Authentication\Tenancy\TenantRequirement>  $requirements
     * @return \Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy
     */
    private function scriptPolicy(array $requirements): ScriptedTenantAuthenticationPolicy
    {
        $policy = new ScriptedTenantAuthenticationPolicy;

        $policy->answer = static function (TenantPolicyContext $context) use ($requirements): TenantRequirement {

            $tenantId = IdentifierCoercion::stringify($context->tenant->getTenantIdentifier()) ?? '';

            return $requirements[$tenantId] ?? new TenantRequirement;
        };

        app()->instance(TenantAuthenticationPolicy::class, $policy);

        return $policy;
    }
}
