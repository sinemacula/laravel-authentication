<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Config\Repository as ConfigRepository;
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
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
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
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
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
 * Feature tests of switching a session to another principal of its identity,
 * another active tenant, or both, proven by the session's refresh token, over
 * HTTP and through the session service: every access token issued before a
 * change stops at once, a lost switch response is answered again inside the
 * grace window, a replay revokes the session, and every check a refresh and a
 * sign-in make runs on every path, with the access contracts asked about the
 * destination.
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
    use InteractsWithProofs, InteractsWithSessions;

    /** @var string Guard over `ActivatableTenantMember`. */
    private const string GUARD = 'members';

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
            $result = Auth::sessions(self::GUARD)->switchTo($request->string('refresh')->toString(), SwitchTarget::principal($target));
            $guard  = app('auth')->guard(self::GUARD);

            assert($guard instanceof JwtGuard);

            return [
                'switched'  => $result->isSwitched(),
                'reason'    => $result->reason?->value,
                'access'    => $result->session?->tokens->accessToken->reveal(),
                'refresh'   => $result->session?->tokens->refreshToken?->reveal(),
                'principal' => $guard->principal()?->getPrincipalIdentifier(),
            ];
        });

        Route::post('/switch-from-request', static fn (Request $request): array => self::switchFromRequest($request));

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
     * Over HTTP, a switch binds the request as the target and hands out its
     * pair; the new access token acts as the target, and the old principal's
     * access token is refused at once, though it has not expired.
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

        $switched = $this->switch($session->tokens->refreshToken?->reveal(), $second)->assertOk();

        $switched->assertJson(['switched' => true, 'reason' => null, 'principal' => $second->getKey()]);

        $this->bearer($switched->json('access'))->assertOk()->assertExactJson(['principal' => $second->getKey()]);
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

        $body = $this->postJson('/switch-from-request', ['refresh_token' => $session->tokens->refreshToken?->reveal(), 'membership' => $second->getKey()])
            ->assertOk()
            ->assertJson(['outcome' => 'switched', 'reason' => null, 'source' => 'body']);

        $this->advance(5);

        Auth::forgetGuards();

        $this->withHeaders(['X-Refresh-Token' => $body->json('refresh')])
            ->postJson('/switch-from-request', ['membership' => $first->getKey()])
            ->assertOk()
            ->assertJson(['outcome' => 'switched', 'source' => 'header']);
    }

    /**
     * A request that carries no refresh token switches nothing and reports
     * nothing; one the transport refuses (a token in two sources) is reported
     * as a `switch` failure with the transport's reason, without the session
     * being touched.
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

        $this->postJson('/switch-from-request', ['membership' => $second->getKey()])
            ->assertOk()
            ->assertExactJson(['outcome' => 'none', 'reason' => null, 'source' => null, 'refresh' => null]);

        self::assertSame([], $this->recorded);

        Auth::forgetGuards();

        $this->withHeaders(['X-Refresh-Token' => $session->tokens->refreshToken?->reveal()])
            ->postJson('/switch-from-request', ['refresh_token' => $session->tokens->refreshToken?->reveal(), 'membership' => $second->getKey()])
            ->assertOk()
            ->assertJson(['outcome' => 'failed', 'reason' => 'refresh_token_conflict', 'source' => null]);

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(AuthenticationFlow::SWITCH, $failure->flow);
        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, $failure->reason);
        self::assertSame(self::GUARD, $failure->context->guard);
        self::assertNull($failure->context->session);
        self::assertSame(PrincipalReference::id($session->principal), DB::table('authentication_sessions')->value('principal_id'));
    }

    /**
     * A switch dispatches the bind events for the target, then
     * `PrincipalSwitched` with the previous principal and tenant (their ids
     * kept apart, so neither is taken for the other) and both changes, but no
     * `Login`; it records the target, the target's own tenant as the active
     * one, the switch time and the rotation on the session, keeps the session's
     * absolute deadline and restarts its idle one, and the guard acts in the
     * target's tenant.
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

        $result = $this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($second));

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
        self::assertTrue($event->context->principal?->is($second)); // @phpstan-ignore method.notFound
        self::assertSame((string) $second->tenant_id, IdentifierCoercion::stringify($event->context->tenant?->getTenantIdentifier()));
        self::assertTrue($event->previousPrincipal?->is($first)); // @phpstan-ignore method.notFound
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

        self::assertSame($idle, self::expiryOf($result->session->tokens->refreshToken?->reveal()));
        self::assertSame($this->now->addMinutes(15)->getTimestamp(), self::expiryOf($result->session->tokens->accessToken->reveal()));
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

        $toSecond = $this->switch($session->tokens->refreshToken?->reveal(), $second)->assertJson(['switched' => true]);

        $this->advance(5);

        $back = $this->switch($toSecond->json('refresh'), $first)->assertJson(['switched' => true, 'principal' => $first->getKey()]);

        $this->bearer($session->tokens->accessToken->reveal())->assertUnauthorized();
        $this->bearer($toSecond->json('access'))->assertUnauthorized();
        $this->bearer($back->json('access'))->assertOk()->assertExactJson(['principal' => $first->getKey()]);
    }

    /**
     * The old principal's refresh token, presented to `refresh()` inside the
     * grace window, fails as `session_principal_mismatch` without revoking; the
     * session goes on.
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

        self::assertNull(self::sessionsOf($this->freshGuard(self::GUARD))->refresh($session->tokens->refreshToken?->reveal())->session);
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(FailureReason::SESSION_PRINCIPAL_MISMATCH, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertNull(DB::table('authentication_sessions')->value('revoked_at'));

        self::assertNotNull(self::sessionsOf($this->freshGuard(self::GUARD))->refresh($switched->tokens->refreshToken?->reveal())->session);
    }

    /**
     * The old principal's refresh token after the grace window is a replay: the
     * session is revoked as `rotation_reuse`, by a switch as by a refresh.
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

        $result = $this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($first));

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
     * A switch whose response was lost is answered again inside the grace
     * window: the old token switched to the same target hands back the current
     * credential, writes nothing and reports no second switch; the same old
     * token to any other principal is a conflict, without revoking.
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

        $row = (array) DB::table('authentication_sessions')->sole();

        $this->advance(5);

        $this->recordEvents([PrincipalSwitched::class, AuthenticationFailed::class, SessionRevoked::class]);

        $retried = $this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($second));

        self::assertTrue($retried->isSwitched());
        self::assertTrue($retried->session?->principal->is($second)); // @phpstan-ignore method.notFound
        self::assertSame([], $this->recordedClasses());
        self::assertEquals($row, (array) DB::table('authentication_sessions')->sole());

        $this->advance(1);

        $conflict = $this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($first));

        self::assertSame(FailureReason::ROTATION_CONFLICT, $conflict->reason);

        DB::table('authentication_sessions')->update(['switched_at' => $this->now->subMinute()]);

        self::assertSame(
            FailureReason::ROTATION_CONFLICT,
            $this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($second))->reason,
        );

        DB::table('authentication_sessions')->update(['switched_at' => $row['switched_at']]);

        $this->bearer($retried->session->tokens->accessToken->reveal())->assertOk()->assertExactJson(['principal' => $second->getKey()]);
        self::assertNotNull(self::sessionsOf($this->freshGuard(self::GUARD))->refresh($retried->session->tokens->refreshToken?->reveal())->session);
        self::assertNull(DB::table('authentication_sessions')->value('revoked_at'));
    }

    /**
     * A switch away from a principal that no longer resolves for the identity
     * still reports what the session recorded for it, without the principal.
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

        self::assertTrue($this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($second))->isSwitched());

        $event = $this->recordedEvent(PrincipalSwitched::class);

        self::assertNull($event->previousPrincipal);
        self::assertSame(ActivatableTenantMembership::class, $event->previousPrincipalType);
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), $event->previousPrincipalId);
    }

    /**
     * A switch away from a principal the session recorded under another type
     * (the morph map changed since) reports the recorded snapshot, but not the
     * principal of the current type that shares its key.
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

        self::assertTrue($this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($second))->isSwitched());

        $event = $this->recordedEvent(PrincipalSwitched::class);

        self::assertNull($event->previousPrincipal);
        self::assertSame('retired-membership', $event->previousPrincipalType);
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), $event->previousPrincipalId);
    }

    /**
     * A member the application lets act in no tenant switches to none: the
     * session records none, the switch reports the tenant it left, and a lost
     * response to it is answered again inside the grace window, in none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchToNoTenantRecordsNoneAndIsAnsweredAgain(): void
    {
        [, , , $own] = $this->seedMemberships();

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

        $session = $this->signIn();

        $this->advance(5);
        $this->recordEvents([PrincipalSwitched::class]);

        $switched = $this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::tenant(TenantSelection::none()));

        self::assertTrue($switched->isSwitched());
        self::assertNull(DB::table('authentication_sessions')->value('tenant_id'));
        self::assertSame(IdentifierCoercion::stringify($own->getKey()), $this->recordedEvent(PrincipalSwitched::class)->previousTenantId);
        self::assertNull($this->recordedEvent(PrincipalSwitched::class)->context->tenant);

        $this->advance(5);

        $retried = $this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::tenant(TenantSelection::none()));

        self::assertTrue($retried->isSwitched());
        self::assertNull(DB::table('authentication_sessions')->value('tenant_id'));
    }

    /**
     * A token of the guard whose rotation id is not a string, though every
     * other check of the token passes, is refused as `token_invalid`, before
     * any session is looked up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenWithoutAStringRotationIdIsRefused(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();
        $claims  = self::claimsOf($session->tokens->refreshToken?->reveal());
        $forged  = JWT::encode([...$claims, 'jti' => 42], 'test-secret-key-with-at-least-32-bytes!', 'HS256', 'test-kid', ['typ' => TokenType::REFRESH->value]);

        self::assertNotNull(Auth::jwt(self::GUARD)->parse($forged, TokenType::REFRESH));

        $this->assertSwitchFails(FailureReason::TOKEN_INVALID, $session, $second, $forged);
    }

    /**
     * A refresh token one refresh old, presented inside the grace window for
     * the principal it already acts as, is answered like a lost refresh
     * response; for another principal it is a conflict.
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

        self::assertNotNull(self::sessionsOf($this->freshGuard(self::GUARD))->refresh($session->tokens->refreshToken?->reveal())->session);

        $own = $this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($first));

        self::assertTrue($own->isSwitched());
        self::assertTrue($own->session?->principal->is($first)); // @phpstan-ignore method.notFound

        self::assertSame(
            FailureReason::ROTATION_CONFLICT,
            $this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($second))->reason,
        );
    }

    /**
     * A switch to the principal the session already acts as rotates the
     * credential like a refresh: no switch is recorded or reported.
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

        $result = $this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($first));

        self::assertTrue($result->isSwitched());
        self::assertSame([], $this->recordedClasses());
        self::assertNull(DB::table('authentication_sessions')->value('switched_at'));
        self::assertSame($this->now->toDateTimeString(), $this->storedTime('refresh_rotated_at'));

        $this->bearer($session->tokens->accessToken->reveal())->assertOk();
        $this->bearer((string) $result->session?->tokens->accessToken->reveal())->assertOk();
    }

    /**
     * A target that is not the identity's, one of another type that shares a
     * key with one of the identity's own, and one whose tenant was deactivated
     * are refused, and the session is left as it was. Each refusal names the
     * session's owner and the target resolved for it, if any, never the
     * principal the session acts as.
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
        $row     = (array) DB::table('authentication_sessions')->sole();

        $mismatch = $this->assertSwitchFails(FailureReason::PRINCIPAL_MISMATCH, $session, $theirs);

        self::assertSame(IdentifierCoercion::stringify($member->getKey()), $mismatch->context->identityId);
        self::assertNull($mismatch->context->principal);
        self::assertNull($mismatch->context->principalType);
        self::assertNull($mismatch->context->principalId);
        self::assertSame(IdentifierCoercion::stringify($session->record->getSessionIdentifier()), $mismatch->context->sessionId);

        $this->assertSwitchFails(FailureReason::PRINCIPAL_MISMATCH, $session, ChoosingMembership::query()->findOrFail($second->getKey()));

        ActivatableTenant::query()->whereKey($second->tenant_id)->update(['is_active' => false]);

        $inactive = $this->assertSwitchFails(FailureReason::TENANT_INACTIVE, $session, $second);

        self::assertSame(IdentifierCoercion::stringify($second->getKey()), $inactive->context->principalId);
        self::assertEquals($row, (array) DB::table('authentication_sessions')->sole());
    }

    /**
     * A switch asks `ApplicationAccess` about its target: a principal it keeps
     * out of the application is refused as `principal_ineligible`, the refusal
     * naming the target, and the session is left as it was.
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
        $row     = (array) DB::table('authentication_sessions')->sole();
        $refused = $this->assertSwitchFails(FailureReason::PRINCIPAL_INELIGIBLE, $session, $second);

        self::assertSame(IdentifierCoercion::stringify($second->getKey()), $refused->context->principalId);
        self::assertEquals($row, (array) DB::table('authentication_sessions')->sole());
    }

    /**
     * Once the guard's application no longer lists the method the session
     * signed in with, or lists nothing, a switch is refused as
     * `method_not_allowed` and the session is left as it was, neither revoked
     * nor rotated; listed again, the same refresh token switches.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchIsRefusedOnceTheSessionsMethodIsNoLongerAllowed(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();
        $row     = (array) DB::table('authentication_sessions')->sole();

        foreach ([['sso'], []] as $methods) {
            config()->set('auth.guards.' . self::GUARD . '.application.methods', $methods);

            $this->assertSwitchFails(FailureReason::METHOD_NOT_ALLOWED, $session, $second);

            self::assertEquals($row, (array) DB::table('authentication_sessions')->sole());
        }

        config()->set('auth.guards.' . self::GUARD . '.application.methods', ['password']);

        self::assertSame($second->getKey(), $this->switched($session, $second)->principal->getPrincipalIdentifier());
    }

    /**
     * A session loaded without the type of identifier its sign-in used is
     * reported rather than switched as if the sign-in used none, which would
     * skip the policy's refusal of the identity with that identifier, and the
     * session stays as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionLoadedWithoutItsIdentifierTypeIsReported(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();
        $row     = (array) DB::table('authentication_sessions')->sole();

        config()->set('authentication.session.model', IdentifierTypeOmittingSession::class);

        try {
            $this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($second));

            self::fail('The switch read a session without its identifier type.');
        } catch (\LogicException $exception) {
            self::assertStringContainsString('its `sign_in_identifier_type` attribute is not loaded', $exception->getMessage());
        }

        self::assertEquals($row, (array) DB::table('authentication_sessions')->sole());
    }

    /**
     * A switch screen that lists the identity's principals, with the identifier
     * type the session records or without one, offers only the targets a switch
     * admits: those `ApplicationAccess` lets use the application.
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
     * A switch asks the application policy about the identity with the
     * session's identifier type before the target, as its sign-in was asked, so
     * a policy that now refuses that identifier for the identity as a whole
     * refuses the switch for its reason without being asked about the target,
     * and leaves the session as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentifierThePolicyRefusesTheIdentityRefusesTheSwitch(): void
    {
        [, $second, $member] = $this->seedMemberships();

        $session = $this->signIn();
        $row     = (array) DB::table('authentication_sessions')->sole();
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

        self::assertEquals($row, (array) DB::table('authentication_sessions')->sole());
    }

    /**
     * Another identity's principal is refused even when the guard's resolver is
     * not scoped to the identity and hands it back: its owner is read from its
     * own stored key.
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
     * A token that is no refresh token of the guard, one naming an unknown
     * session, and one whose session belongs to another guard are refused
     * before anything is switched.
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

        DB::table('authentication_sessions')->delete();

        $this->assertSwitchFails(FailureReason::SESSION_UNKNOWN, $session, $second);
    }

    /**
     * A switch on a revoked session or an ended session fails for that reason
     * and revokes nothing further. The failure is about the session row, read
     * before its owner, so it names the owner and the principal the row
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

        self::assertNull($revoked->context->identity);
        self::assertNull($revoked->context->principal);
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
     * The switched session's absolute deadline is held to the guard's absolute
     * lifetime counted from the sign-in, so one the guard shortened after the
     * session started applies and a switch never extends the session, and a
     * session already past it fails as `session_expired`.
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

        self::assertNotNull($this->sessions(self::GUARD)->switchTo($later->tokens->refreshToken?->reveal(), SwitchTarget::principal($second))->session);

        $latest = $this->signIn();

        $this->advance(600);

        $this->assertSwitchFails(FailureReason::SESSION_EXPIRED, $latest, $second);
    }

    /**
     * A switch of a session with no absolute deadline, under a guard that sets
     * no absolute limit, adds none: the session still ends only when it goes
     * idle, its idle deadline restarted from the switch.
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
     * A session with no recorded start, which a custom schema may allow, and no
     * absolute deadline is switched with none: with no start to count a limit
     * from, the deadline it stores stands.
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
     * A session that started with no absolute deadline is held, at its next
     * switch, to an absolute limit the guard set since, counted from the
     * sign-in: a switch only ever lowers the absolute deadline.
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
     * A session the guard's shortened absolute lifetime has ended fails as
     * `session_expired` from the second of that deadline, although the deadline
     * it stored when it started under the longer lifetime is still ahead, and
     * the session is left as it was.
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
        $before  = (array) DB::table('authentication_sessions')->first();

        $this->advance(600);

        self::assertGreaterThan($this->now->toDateTimeString(), $this->storedTime('absolute_expires_at'));

        $this->assertSwitchFails(FailureReason::SESSION_EXPIRED, $session, $second);

        self::assertSame($before, (array) DB::table('authentication_sessions')->first());
    }

    /**
     * A switch whose session or client has no attempts left fails as
     * `rate_limited` with the wait, without looking the session up; a failed
     * switch counts against the refresh limits of the token's session and the
     * client.
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

        $blocked = $this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($second));

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
            $this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($second))->reason,
        );
    }

    /**
     * A switch takes no further factor from the identity-level factor policy:
     * the destination tenant's policy is the one asked, so a policy that would
     * ask every sign-in for one does not refuse the switch.
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
        $factors->shouldNotReceive('requiresAdditionalFactor');

        app()->instance(AdditionalFactorPolicy::class, $factors);

        $this->advance(5);

        self::assertSame($second->getKey(), $this->switched($session, $second)->principal->getPrincipalIdentifier());
    }

    /**
     * A switch that names only a tenant keeps the principal the session acts as
     * and moves the session to that tenant: the row records it and the time of
     * the switch, `PrincipalSwitched` reports the tenant change alone with the
     * tenant left, the guard acts in the new tenant, the access token issued
     * before is refused at once as `session_tenant_mismatch`, and the new one
     * acts in the new tenant.
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

        $result = $this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::tenant(TenantSelection::of($descendant->getKey())));

        self::assertTrue($result->isSwitched());
        self::assertTrue($result->session?->principal->is($first)); // @phpstan-ignore method.notFound
        self::assertSame([PrincipalSwitched::class], $this->recordedClasses());

        $event = $this->recordedEvent(PrincipalSwitched::class);

        self::assertFalse($event->principalChanged);
        self::assertTrue($event->tenantChanged);
        self::assertSame(IdentifierCoercion::stringify($own->getKey()), $event->previousTenantId);
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), $event->previousPrincipalId);
        self::assertTrue($event->previousPrincipal?->is($first)); // @phpstan-ignore method.notFound
        self::assertTrue($event->context->principal?->is($first)); // @phpstan-ignore method.notFound
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
     * A switch that names a principal and a tenant moves the session to both at
     * once, and `PrincipalSwitched` reports both changes; without a tenant, the
     * principal's own is its default.
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

        $result = $this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($second, TenantSelection::of($descendant->getKey())));

        self::assertTrue($result->session?->principal->is($second)); // @phpstan-ignore method.notFound

        $event = $this->recordedEvent(PrincipalSwitched::class);

        self::assertTrue($event->principalChanged);
        self::assertTrue($event->tenantChanged);
        self::assertSame(IdentifierCoercion::stringify($own->getKey()), $event->previousTenantId);
        self::assertTrue($event->previousPrincipal?->is($first)); // @phpstan-ignore method.notFound

        $record = DB::table('authentication_sessions')->sole();

        self::assertSame(IdentifierCoercion::stringify($second->getKey()), IdentifierCoercion::stringify($record->principal_id));
        self::assertSame(IdentifierCoercion::stringify($descendant->getKey()), $record->tenant_id);

        $this->assertRefusedAs(FailureReason::SESSION_TENANT_MISMATCH, $session->tokens->accessToken->reveal());
        $this->tenantOf($result->session->tokens->accessToken->reveal())->assertOk()->assertExactJson(['tenant' => IdentifierCoercion::stringify($descendant->getKey())]);
    }

    /**
     * Switching back to the tenant a session acted in before does not revive
     * the tokens issued there: the first token, though it names that tenant and
     * principal again, was issued before the last switch and is refused as
     * `session_switched`; the one issued in the other tenant is refused as
     * `session_tenant_mismatch`; only the latest is accepted.
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

        $away = $this->switchedTo($session->tokens->refreshToken?->reveal(), SwitchTarget::tenant(TenantSelection::of($descendant->getKey())));

        $this->advance(5);

        $back = $this->switchedTo($away->tokens->refreshToken?->reveal(), SwitchTarget::tenant(TenantSelection::principalDefault()));

        self::assertSame(IdentifierCoercion::stringify($own->getKey()), DB::table('authentication_sessions')->value('tenant_id'));
        self::assertSame($this->now->toDateTimeString(), $this->storedTime('switched_at'));

        $this->assertRefusedAs(FailureReason::SESSION_SWITCHED, $session->tokens->accessToken->reveal());
        $this->assertRefusedAs(FailureReason::SESSION_TENANT_MISMATCH, $away->tokens->accessToken->reveal());

        $this->tenantOf($back->tokens->accessToken->reveal())->assertOk()->assertExactJson(['tenant' => IdentifierCoercion::stringify($own->getKey())]);
    }

    /**
     * Two switches in one second, there and back, still refuse every token
     * issued before the second: it records the switch one second after the
     * first, so the tokens it issues itself are refused as `session_switched`
     * until the client refreshes in the next second, and the refreshed token is
     * accepted.
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

        $away = $this->switchedTo($session->tokens->refreshToken?->reveal(), SwitchTarget::tenant(TenantSelection::of($descendant->getKey())));
        $back = $this->switchedTo($away->tokens->refreshToken?->reveal(), SwitchTarget::tenant(TenantSelection::principalDefault()));

        self::assertSame($this->now->addSecond()->toDateTimeString(), $this->storedTime('switched_at'));

        $this->assertRefusedAs(FailureReason::SESSION_SWITCHED, $session->tokens->accessToken->reveal());
        $this->assertRefusedAs(FailureReason::SESSION_TENANT_MISMATCH, $away->tokens->accessToken->reveal());
        $this->assertRefusedAs(FailureReason::SESSION_SWITCHED, $back->tokens->accessToken->reveal());

        $this->advance(1);

        $refreshed = self::sessionsOf($this->freshGuard(self::GUARD))->refresh($back->tokens->refreshToken?->reveal())->session;

        self::assertNotNull($refreshed);

        $this->tenantOf($refreshed->tokens->accessToken->reveal())->assertOk()->assertExactJson(['tenant' => IdentifierCoercion::stringify($own->getKey())]);
    }

    /**
     * A switch to the tenant the session already acts in, for the principal it
     * already acts as, rotates the credential like a refresh: nothing records a
     * switch, nothing reports one, and the access token issued before still
     * works.
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

        $result = $this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::tenant(TenantSelection::of($own->getKey())));

        self::assertTrue($result->isSwitched());
        self::assertSame([], $this->recordedClasses());
        self::assertNull(DB::table('authentication_sessions')->value('switched_at'));
        self::assertSame($this->now->toDateTimeString(), $this->storedTime('refresh_rotated_at'));

        $this->bearer($session->tokens->accessToken->reveal())->assertOk();
    }

    /**
     * A destination tenant the access contracts do not let the principal act in
     * is refused, the session left as it was: one the default resolver cannot
     * find, no tenant at all for a principal that belongs to one
     * (`tenant_ineligible`), and one the application's tree lets it act in but
     * that is deactivated (`tenant_inactive`). The refusal names the principal
     * the switch admitted.
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
        $row     = (array) DB::table('authentication_sessions')->sole();

        $foreign = $this->assertTargetFails(FailureReason::TENANT_INELIGIBLE, $session, SwitchTarget::tenant(TenantSelection::of($other->getKey())));

        self::assertSame(IdentifierCoercion::stringify($first->getKey()), $foreign->context->principalId);

        $this->assertTargetFails(FailureReason::TENANT_INELIGIBLE, $session, SwitchTarget::tenant(TenantSelection::none()));

        $descendant = $this->below($own);

        $descendant->forceFill(['is_active' => false])->save();

        $this->assertTargetFails(FailureReason::TENANT_INACTIVE, $session, SwitchTarget::tenant(TenantSelection::of($descendant->getKey())));

        self::assertEquals($row, (array) DB::table('authentication_sessions')->sole());
    }

    /**
     * A tenant-only switch is held to the principal the session records, as a
     * refresh holds it: once the principal's own tenant is deactivated the
     * switch is refused as `tenant_inactive` before the destination tenant is
     * asked about, though the application's tree would let it act there.
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

        $refused = $this->assertTargetFails(FailureReason::TENANT_INACTIVE, $session, SwitchTarget::tenant(TenantSelection::of($descendant->getKey())));

        self::assertSame(IdentifierCoercion::stringify($first->getKey()), $refused->context->principalId);
        self::assertSame($asked, $this->tree()->asked);
        self::assertSame($resolved, $this->tree()->resolved);
    }

    /**
     * A switch keeps the session's key, so the proofs of its sign-in carry over
     * unchanged: the same rows, and the new access token carries the same
     * `auth_time` and `amr` as the one before.
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
     * A switch whose destination tenant requires connections the session was
     * not established through is refused as `sso_required`, reported for the
     * `switch` flow, and leaves the session as it was, acting in its current
     * tenant with its tokens still good.
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
        $row     = (array) DB::table('authentication_sessions')->sole();

        $this->advance(5);

        $asked   = count($policy->asked);
        $refused = $this->assertSwitchFails(FailureReason::SSO_REQUIRED, $session, $second);

        self::assertSame(IdentifierCoercion::stringify($second->getKey()), $refused->context->principalId);
        self::assertSame(IdentifierCoercion::stringify($second->tenant_id), $refused->context->tenantId);
        self::assertEquals($row, (array) DB::table('authentication_sessions')->sole());
        self::assertCount($asked + 1, $policy->asked);

        $this->bearer($session->tokens->accessToken->reveal())->assertOk();
    }

    /**
     * A switch whose destination tenant asks for a further factor the session
     * lacks returns the session to pending with the destination recorded,
     * instead of re-issuing its pair: the result is pending with a credential,
     * `SessionReturnedToPending` reports the `switch` flow, nothing reports a
     * switch, the access token issued before is refused at once, and the
     * refresh token is refused as `session_pending`, not as a replay. Once a
     * further factor is satisfied, the session activates in the destination,
     * acting as the target in its tenant, and reports `SessionActivated`.
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

        $result = $this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($second));

        self::assertTrue($result->isPending());
        self::assertFalse($result->isSwitched());
        self::assertFalse($result->isFailed());
        self::assertNull($result->session);
        self::assertNotNull($result->credential);
        self::assertNotNull($result->pending);
        self::assertSame([PendingRequirement::MFA], $result->pending->requires);
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

        self::assertSame(FailureReason::SESSION_PENDING, self::sessionsOf($this->freshGuard(self::GUARD))->refresh($session->tokens->refreshToken?->reveal())->reason);
        self::assertNull(DB::table('authentication_sessions')->value('revoked_at'));

        $this->advance(1);

        $this->recordEvents([SessionActivated::class]);

        $active = $this->sessions(self::GUARD)->satisfy($result->credential->reveal(), self::adapterProof($member, self::GUARD, $result->pending->id, Purpose::SIGN_IN));

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
     * A switch that returns the session to pending forgets a binding of the
     * guard to that session in the same request, with no event, so nothing
     * later in the request acts as the principal or in the tenant it left.
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

        self::assertTrue($service->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($second))->isPending());
        self::assertFalse($guard->hasUser());
        self::assertNull($guard->user());
        self::assertNull($guard->principal());
        self::assertNull($guard->session());
        self::assertNull($guard->tenant());
    }

    /**
     * A switch whose destination's further factor the session already meets
     * switches as one with no requirement, and records the version the policy
     * answered; the requirement check is asked once.
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
     * A tenant-only switch is held to the destination tenant's policy too: a
     * tenant below the principal's own that requires connections refuses it,
     * and the session stays in its own tenant.
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

        $this->assertTargetFails(FailureReason::SSO_REQUIRED, $session, SwitchTarget::tenant(TenantSelection::of($descendant->getKey())));

        self::assertSame(IdentifierCoercion::stringify($own->getKey()), DB::table('authentication_sessions')->value('tenant_id'));
    }

    /**
     * A lost response to a switch made in a second the session's floor already
     * reached is still answered inside the grace window: that switch moved the
     * floor one second past its rotation, and the retry, presenting a token of
     * the principal switched from, is still known for a switch.
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
        $back = $this->switchedTo($away->tokens->refreshToken?->reveal(), SwitchTarget::principal($first));

        self::assertNotSame($this->storedTime('refresh_rotated_at'), $this->storedTime('switched_at'));
        self::assertTrue($first->is($back->principal));

        $row = (array) DB::table('authentication_sessions')->sole();

        $this->recordEvents([PrincipalSwitched::class, AuthenticationFailed::class]);

        $retried = $this->sessions(self::GUARD)->switchTo($away->tokens->refreshToken?->reveal(), SwitchTarget::principal($first));

        self::assertTrue($retried->isSwitched());
        self::assertTrue($first->is($retried->session?->principal));
        self::assertSame([], $this->recordedClasses());
        self::assertEquals($row, (array) DB::table('authentication_sessions')->sole());
    }

    /**
     * A grace retry of a switch to the context the session already acts in is
     * held to the tenant's authentication policy as a refresh with the same
     * token is: once the tenant requires a connection the session was not
     * established through it is refused as `sso_required`, leaving the session
     * as it was, and once it asks for a further factor the session lacks the
     * session returns to pending, so the retry is never a refresh that skips
     * the policy.
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

        self::assertNotNull(self::sessionsOf($this->freshGuard(self::GUARD))->refresh($session->tokens->refreshToken?->reveal())->session);

        $this->advance(1);

        $tenant = IdentifierCoercion::stringify($own->getKey()) ?? '';
        $target = SwitchTarget::tenant(TenantSelection::principalDefault());

        $this->scriptPolicy([$tenant => new TenantRequirement('v1', connections: ['conn-a'])]);

        $row = (array) DB::table('authentication_sessions')->sole();

        $this->assertTargetFails(FailureReason::SSO_REQUIRED, $session, $target);

        self::assertEquals($row, (array) DB::table('authentication_sessions')->sole());

        $this->scriptPolicy([$tenant => new TenantRequirement('v2', new Requirement(new RequirementPart))]);

        $this->recordEvents([SessionReturnedToPending::class, PrincipalSwitched::class]);

        $returned = $this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), $target);

        self::assertTrue($returned->isPending());
        self::assertNull($returned->session);
        self::assertNotNull($returned->credential);
        self::assertSame([SessionReturnedToPending::class], $this->recordedClasses());
        self::assertSame(AuthenticationFlow::SWITCH, $this->recordedEvent(SessionReturnedToPending::class)->flow);
        self::assertSame('pending', DB::table('authentication_sessions')->value('status'));
    }

    /**
     * A bind listener that throws fails a switch after it was written, but
     * `PrincipalSwitched` was scheduled before the bind, so the switch is
     * reported; inside a caller's transaction it waits for the commit, and a
     * rollback withdraws it and leaves the session as it was.
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

        DB::beginTransaction();

        self::assertSame('listener failed', $this->failedSwitch($session->tokens->refreshToken?->reveal(), $second));
        self::assertSame([], $this->recordedClasses());

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertEquals($before, (array) DB::table('authentication_sessions')->sole());

        self::assertSame('listener failed', $this->failedSwitch($session->tokens->refreshToken?->reveal(), $second));
        self::assertSame([PrincipalSwitched::class], $this->recordedClasses());
        self::assertSame(IdentifierCoercion::stringify($second->getKey()), IdentifierCoercion::stringify(DB::table('authentication_sessions')->value('principal_id')));
    }

    /**
     * Inside a caller's transaction that catches a switch's throwing bind
     * listener and commits, `PrincipalSwitched` follows the commit, once, and
     * the session stays switched.
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

        self::assertSame('listener failed', $this->failedSwitch($session->tokens->refreshToken?->reveal(), $second));
        self::assertSame([], $this->recordedClasses());

        DB::commit();

        self::assertSame([PrincipalSwitched::class], $this->recordedClasses());
        self::assertSame(IdentifierCoercion::stringify($second->getKey()), IdentifierCoercion::stringify(DB::table('authentication_sessions')->value('principal_id')));
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

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * Switch to the membership named with the refresh token the request
     * carries, and answer with the outcome, its reason and source, and the new
     * refresh token.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array<string, ?string>
     *
     * @throws \Throwable
     */
    private static function switchFromRequest(Request $request): array
    {
        $result = Auth::sessions(self::GUARD)->switchFromRequest(SwitchTarget::principal(ActivatableTenantMembership::query()->findOrFail($request->integer('membership'))));

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
     * Sign the member in as its default membership, named at sign-in: a member
     * with more than one membership would otherwise be held pending for the
     * choice.
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
        $switched = $this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), SwitchTarget::principal($target))->session;

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

        $result = $this->sessions(self::GUARD)->switchTo($token ?? $session->tokens->refreshToken?->reveal(), SwitchTarget::principal($target));

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
            $this->sessions(self::GUARD)->switchTo($refreshToken, SwitchTarget::principal($principal));
        } catch (\RuntimeException $exception) {
            return $exception->getMessage();
        }

        self::fail('Expected the listener to throw.');
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

        $this->tree()->place($descendant->getKey(), $tenant->getKey());

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
        $switched = $this->sessions(self::GUARD)->switchTo($refreshToken, $target)->session;

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

        $result = $this->sessions(self::GUARD)->switchTo($session->tokens->refreshToken?->reveal(), $target);

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
     * Bind a tenant authentication policy that answers each tenant with the
     * requirement given for its identifier, and nothing for any other, and
     * return it.
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
