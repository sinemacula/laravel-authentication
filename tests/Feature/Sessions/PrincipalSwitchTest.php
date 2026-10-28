<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Login;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\AttemptLimiter;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\PrincipalSwitched;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenServiceFactory;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\RateLimiting\AttemptSubject;
use SineMacula\Laravel\Authentication\RateLimiting\Enums\AttemptFlow;
use SineMacula\Laravel\Authentication\Sessions\Concerns\ChoosesPrincipals;
use SineMacula\Laravel\Authentication\Sessions\PrincipalReference;
use SineMacula\Laravel\Authentication\Sessions\PrincipalSwitch;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SwitchedPrincipal;
use SineMacula\Laravel\Authentication\Sessions\SwitchResult;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\ChoosingMembership;
use Tests\Integration\Fixtures\UnscopedMembershipResolver;
use Tests\TestCase;

/**
 * Feature tests of switching a session to another principal of its identity,
 * proven by the session's refresh token, over HTTP and through the session
 * service: the old principal's tokens stop at once, a lost switch response is
 * answered again inside the grace window, a replay revokes the device, and
 * every check a refresh and a sign-in make runs on every path.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrincipalSwitch::class)]
#[CoversClass(SessionService::class)]
#[CoversClass(SwitchedPrincipal::class)]
#[CoversClass(SwitchResult::class)]
#[CoversClass(PrincipalSwitched::class)]
#[CoversTrait(ChoosesPrincipals::class)]
final class PrincipalSwitchTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string Guard over `ActivatableTenantMember`. */
    private const string GUARD = 'members';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

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
            $result = Auth::sessions(self::GUARD)->switchPrincipal($request->string('refresh')->toString(), $target);
            $guard  = app('auth')->guard(self::GUARD);

            assert($guard instanceof JwtGuard);

            return [
                'switched'  => $result->isSwitched(),
                'reason'    => $result->reason?->value,
                'access'    => $result->session?->tokens->accessToken,
                'refresh'   => $result->session?->tokens->refreshToken,
                'principal' => $guard->principal()?->getPrincipalIdentifier(),
            ];
        });

        Route::post('/switch-from-request', static fn (Request $request): array => self::switchFromRequest($request));

        Route::middleware('auth:' . self::GUARD)->get('/me', static fn (): array => ['principal' => Auth::principal()?->getPrincipalIdentifier()]);
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

        $switched = $this->switch($session->tokens->refreshToken, $second)->assertOk();

        $switched->assertJson(['switched' => true, 'reason' => null, 'principal' => $second->getKey()]);

        $this->bearer($switched->json('access'))->assertOk()->assertExactJson(['principal' => $second->getKey()]);
        $this->bearer($session->tokens->accessToken)->assertUnauthorized();

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

        $body = $this->postJson('/switch-from-request', ['refresh_token' => $session->tokens->refreshToken, 'membership' => $second->getKey()])
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
     * as a `principal_switch` failure with the transport's reason, without the
     * device being touched.
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

        $this->withHeaders(['X-Refresh-Token' => $session->tokens->refreshToken])
            ->postJson('/switch-from-request', ['refresh_token' => $session->tokens->refreshToken, 'membership' => $second->getKey()])
            ->assertOk()
            ->assertJson(['outcome' => 'failed', 'reason' => 'refresh_token_conflict', 'source' => null]);

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(AuthenticationFlow::PRINCIPAL_SWITCH, $failure->flow);
        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, $failure->reason);
        self::assertSame(self::GUARD, $failure->context->guard);
        self::assertNull($failure->context->device);
        self::assertSame(PrincipalReference::id($session->principal), DB::table('devices')->value('principal_id'));
    }

    /**
     * A switch dispatches the bind events for the target, then
     * `PrincipalSwitched` with the previous principal, but no `Login`; it
     * records the target, the switch time and the rotation on the device, keeps
     * the session's absolute deadline and restarts its idle one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchRecordsTheTargetAndReportsTheSwitch(): void
    {
        [$first, $second, $member] = $this->seedMemberships();

        $session  = $this->signIn();
        $absolute = DB::table('devices')->value('absolute_expires_at');

        $this->advance(60);

        $this->recordEvents([Authenticated::class, PrincipalAssigned::class, DeviceAuthenticated::class, PrincipalSwitched::class, Login::class]);

        $result = $this->sessions(self::GUARD)->switchPrincipal($session->tokens->refreshToken, $second);

        self::assertTrue($result->isSwitched());
        self::assertFalse($result->isFailed());
        self::assertNull($result->reason);
        self::assertNotNull($result->session);
        self::assertTrue($result->session->principal->is($second)); // @phpstan-ignore method.notFound
        self::assertTrue($result->session->identity->is($member)); // @phpstan-ignore method.notFound
        self::assertFalse($result->session->deviceCreated);
        self::assertSame('password', $result->session->method);

        self::assertSame([Authenticated::class, PrincipalAssigned::class, DeviceAuthenticated::class, PrincipalSwitched::class], $this->recordedClasses());

        $event = $this->recordedEvent(PrincipalSwitched::class);

        self::assertSame(self::GUARD, $event->context->guard);
        self::assertTrue($event->context->principal?->is($second)); // @phpstan-ignore method.notFound
        self::assertSame((string) $second->tenant_id, IdentifierCoercion::stringify($event->context->tenant?->getTenantIdentifier()));
        self::assertTrue($event->previousPrincipal?->is($first)); // @phpstan-ignore method.notFound
        self::assertSame(ActivatableTenantMembership::class, $event->previousPrincipalType);
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), $event->previousPrincipalId);
        self::assertSame('password', $event->context->method);

        $device = DB::table('devices')->sole();

        self::assertSame((string) $second->getKey(), (string) $device->principal_id); // @phpstan-ignore cast.string
        self::assertSame($this->now->toDateTimeString(), CarbonImmutable::parse($device->principal_switched_at)->toDateTimeString());
        self::assertSame($this->now->toDateTimeString(), CarbonImmutable::parse($device->refresh_rotated_at)->toDateTimeString());
        self::assertSame($absolute, $device->absolute_expires_at);
        self::assertSame($this->now->addMinutes(60 * 24 * 30)->toDateTimeString(), CarbonImmutable::parse($device->idle_expires_at)->toDateTimeString());

        self::assertTrue(Auth::guard(self::GUARD)->principal()?->is($second)); // @phpstan-ignore method.notFound

        $idle = $this->now->addMinutes(60 * 24 * 30)->getTimestamp();

        self::assertSame($idle, self::expiryOf($result->session->tokens->refreshToken));
        self::assertSame($this->now->addMinutes(15)->getTimestamp(), self::expiryOf($result->session->tokens->accessToken));
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

        $toSecond = $this->switch($session->tokens->refreshToken, $second)->assertJson(['switched' => true]);

        $this->advance(5);

        $back = $this->switch($toSecond->json('refresh'), $first)->assertJson(['switched' => true, 'principal' => $first->getKey()]);

        $this->bearer($session->tokens->accessToken)->assertUnauthorized();
        $this->bearer($toSecond->json('access'))->assertUnauthorized();
        $this->bearer($back->json('access'))->assertOk()->assertExactJson(['principal' => $first->getKey()]);
    }

    /**
     * The old principal's refresh token, presented to `refresh()` inside the
     * grace window, fails as `device_principal_mismatch` without revoking; the
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

        $this->recordEvents([AuthenticationFailed::class, DeviceRevoked::class]);

        self::assertNull($this->freshGuard(self::GUARD)->refresh($session->tokens->refreshToken));
        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(FailureReason::DEVICE_PRINCIPAL_MISMATCH, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertNull(DB::table('devices')->value('revoked_at'));

        self::assertNotNull($this->freshGuard(self::GUARD)->refresh($switched->tokens->refreshToken));
    }

    /**
     * The old principal's refresh token after the grace window is a replay: the
     * device is revoked as `rotation_reuse`, by a switch as by a refresh.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheOldRefreshTokenAfterTheGraceWindowRevokesTheDevice(): void
    {
        [$first, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);
        $this->switched($session, $second);
        $this->advance(31);

        $this->recordEvents([AuthenticationFailed::class, DeviceRevoked::class]);

        $result = $this->sessions(self::GUARD)->switchPrincipal($session->tokens->refreshToken, $first);

        self::assertTrue($result->isFailed());
        self::assertSame(FailureReason::ROTATION_REUSE, $result->reason);
        self::assertSame([DeviceRevoked::class, AuthenticationFailed::class], $this->recordedClasses());
        self::assertSame(RevocationReason::ROTATION_REUSE, $this->recordedEvent(DeviceRevoked::class)->reason);
        self::assertSame(self::CLIENT_IP, $this->recordedEvent(DeviceRevoked::class)->context->client->ip);

        $failed = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(AuthenticationFlow::PRINCIPAL_SWITCH, $failed->flow);
        self::assertSame(self::GUARD, $failed->context->guard);
        self::assertSame('password', $failed->context->method);
        self::assertSame('rotation_reuse', DB::table('devices')->value('revoked_reason'));
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

        $row = (array) DB::table('devices')->sole();

        $this->advance(5);

        $this->recordEvents([PrincipalSwitched::class, AuthenticationFailed::class, DeviceRevoked::class]);

        $retried = $this->sessions(self::GUARD)->switchPrincipal($session->tokens->refreshToken, $second);

        self::assertTrue($retried->isSwitched());
        self::assertTrue($retried->session?->principal->is($second)); // @phpstan-ignore method.notFound
        self::assertSame([], $this->recordedClasses());
        self::assertEquals($row, (array) DB::table('devices')->sole());

        $this->advance(1);

        $conflict = $this->sessions(self::GUARD)->switchPrincipal($session->tokens->refreshToken, $first);

        self::assertSame(FailureReason::ROTATION_CONFLICT, $conflict->reason);

        DB::table('devices')->update(['principal_switched_at' => $this->now->subMinute()]);

        self::assertSame(FailureReason::ROTATION_CONFLICT, $this->sessions(self::GUARD)->switchPrincipal($session->tokens->refreshToken, $second)->reason);

        DB::table('devices')->update(['principal_switched_at' => $row['principal_switched_at']]);

        $this->bearer($retried->session->tokens->accessToken)->assertOk()->assertExactJson(['principal' => $second->getKey()]);
        self::assertNotNull($this->freshGuard(self::GUARD)->refresh($retried->session->tokens->refreshToken));
        self::assertNull(DB::table('devices')->value('revoked_at'));
    }

    /**
     * A switch away from a principal that no longer resolves for the identity
     * still reports what the device recorded for it, without the principal.
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

        self::assertTrue($this->sessions(self::GUARD)->switchPrincipal($session->tokens->refreshToken, $second)->isSwitched());

        $event = $this->recordedEvent(PrincipalSwitched::class);

        self::assertNull($event->previousPrincipal);
        self::assertSame(ActivatableTenantMembership::class, $event->previousPrincipalType);
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), $event->previousPrincipalId);
    }

    /**
     * A switch away from a principal the device recorded under another type
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

        DB::table('devices')->update(['principal_type' => 'retired-membership']);

        $this->recordEvents([PrincipalSwitched::class]);

        self::assertTrue($this->sessions(self::GUARD)->switchPrincipal($session->tokens->refreshToken, $second)->isSwitched());

        $event = $this->recordedEvent(PrincipalSwitched::class);

        self::assertNull($event->previousPrincipal);
        self::assertSame('retired-membership', $event->previousPrincipalType);
        self::assertSame(IdentifierCoercion::stringify($first->getKey()), $event->previousPrincipalId);
    }

    /**
     * A token of the guard whose rotation id is not a string is refused as
     * `token_invalid`, before any device is looked up.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenWithoutAStringRotationIdIsRefused(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();
        $claims  = self::claimsOf($session->tokens->refreshToken);
        $forged  = JWT::encode([...$claims, 'jti' => 42], 'test-secret-key-with-at-least-32-bytes!', 'HS256', 'test-kid');

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

        self::assertNotNull($this->freshGuard(self::GUARD)->refresh($session->tokens->refreshToken));

        $own = $this->sessions(self::GUARD)->switchPrincipal($session->tokens->refreshToken, $first);

        self::assertTrue($own->isSwitched());
        self::assertTrue($own->session?->principal->is($first)); // @phpstan-ignore method.notFound

        self::assertSame(FailureReason::ROTATION_CONFLICT, $this->sessions(self::GUARD)->switchPrincipal($session->tokens->refreshToken, $second)->reason);
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

        $result = $this->sessions(self::GUARD)->switchPrincipal($session->tokens->refreshToken, $first);

        self::assertTrue($result->isSwitched());
        self::assertSame([], $this->recordedClasses());
        self::assertNull(DB::table('devices')->value('principal_switched_at'));
        self::assertSame($this->now->toDateTimeString(), $this->storedTime('refresh_rotated_at'));

        $this->bearer($session->tokens->accessToken)->assertOk();
        $this->bearer((string) $result->session?->tokens->accessToken)->assertOk();
    }

    /**
     * A target that is not the identity's, one of another type that shares a
     * key with one of the identity's own, one whose tenant was deactivated, and
     * one the factor policy would ask a further factor of are refused, and the
     * session is left as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATargetTheIdentityMayNotActAsIsRefused(): void
    {
        [, $second, , $tenant] = $this->seedMemberships();

        [, $theirs] = $this->seedMember('other@example.test', $tenant);

        $session = $this->signIn();
        $row     = (array) DB::table('devices')->sole();

        $this->assertSwitchFails(FailureReason::PRINCIPAL_MISMATCH, $session, $theirs);
        $this->assertSwitchFails(FailureReason::PRINCIPAL_MISMATCH, $session, ChoosingMembership::query()->findOrFail($second->getKey()));

        $factors = \Mockery::mock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requiresAdditionalFactor')
            ->once()
            ->andReturnUsing(static fn (AdditionalFactorContext $context): bool => $context->principal->is($second) // @phpstan-ignore method.notFound
                && $context->provenDevice?->getDeviceIdentifier() === $session->device->getDeviceIdentifier()
                && $context->method                               === 'password'
                && $context->guard                                === self::GUARD);

        app()->instance(AdditionalFactorPolicy::class, $factors);

        $this->assertSwitchFails(FailureReason::ADDITIONAL_FACTOR_REQUIRED, $session, $second);

        app()->forgetInstance(AdditionalFactorPolicy::class);

        ActivatableTenant::query()->whereKey($second->tenant_id)->update(['is_active' => false]);

        $this->assertSwitchFails(FailureReason::TENANT_INACTIVE, $session, $second);

        self::assertEquals($row, (array) DB::table('devices')->sole());
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
     * device, and one whose device belongs to another guard are refused before
     * anything is switched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenThatProvesNoSessionOfTheGuardIsRefused(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->assertSwitchFails(FailureReason::TOKEN_INVALID, $session, $second, $session->tokens->accessToken);

        DB::table('devices')->update(['guard' => 'admin']);

        $this->assertSwitchFails(FailureReason::DEVICE_GUARD_MISMATCH, $session, $second);

        DB::table('devices')->delete();

        $this->assertSwitchFails(FailureReason::DEVICE_UNKNOWN, $session, $second);
    }

    /**
     * A switch on a revoked device or an ended session fails for that reason
     * and revokes nothing further.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchOnAnEndedSessionIsRefused(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        DB::table('devices')->update(['idle_expires_at' => $this->now->subSecond()]);

        $this->assertSwitchFails(FailureReason::SESSION_EXPIRED, $session, $second);

        DB::table('devices')->update(['revoked_at' => $this->now, 'revoked_reason' => 'revoked']);

        $this->assertSwitchFails(FailureReason::DEVICE_REVOKED, $session, $second);
    }

    /**
     * A switch whose token names a principal the device no longer records fails
     * as `device_principal_mismatch`, without revoking.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenForAnotherPrincipalThanTheDeviceRecordsIsRefused(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        DB::table('devices')->update(['principal_id' => IdentifierCoercion::stringify($second->getKey())]);

        $this->assertSwitchFails(FailureReason::DEVICE_PRINCIPAL_MISMATCH, $session, $second);

        self::assertNull(DB::table('devices')->value('revoked_at'));
    }

    /**
     * The switched session's absolute deadline is held to the target type's
     * absolute lifetime counted from the sign-in, and a session already past it
     * fails as `session_expired`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheTargetTypesLifetimeBoundsTheSwitchedSession(): void
    {
        [, $second] = $this->seedMemberships();

        $guard    = app(JwtTokenServiceFactory::class)->forGuard(self::GUARD)->lifetimes();
        $short    = new TokenLifetimes(5, 60, 10, 30);
        $audience = \Mockery::mock(AudiencePolicy::class);
        $audience->shouldReceive('allowsMethod')->andReturnTrue();
        $audience->shouldReceive('admit')->andReturnNull();
        $audience->shouldReceive('lifetimes')
            ->andReturnUsing(static fn (string $name, Principal $principal): TokenLifetimes => $principal->is($second) ? $short : $guard); // @phpstan-ignore method.notFound

        app()->instance(AudiencePolicy::class, $audience);

        $session = $this->signIn();
        $signIn  = $this->now;

        $this->advance(60);

        $switched = $this->switched($session, $second);

        self::assertSame($signIn->addMinutes(10)->getTimestamp(), $switched->device->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertSame($signIn->addMinutes(10)->toDateTimeString(), $this->storedTime('absolute_expires_at'));
        self::assertSame($signIn->addMinutes(10)->toDateTimeString(), $this->storedTime('idle_expires_at'));

        $later = $this->signIn();

        $this->advance(599);

        self::assertNotNull($this->sessions(self::GUARD)->switchPrincipal($later->tokens->refreshToken, $second)->session);

        $latest = $this->signIn();

        $this->advance(600);

        $this->assertSwitchFails(FailureReason::SESSION_EXPIRED, $latest, $second);
    }

    /**
     * A switch whose device or client has no attempts left fails as
     * `rate_limited` with the wait, without looking the device up; a failed
     * switch counts against the refresh limits of the token's device and the
     * client.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSwitchesAreBoundedByTheRefreshLimits(): void
    {
        [, $second] = $this->seedMemberships();

        $session  = $this->signIn();
        $deviceId = IdentifierCoercion::stringify($session->device->getDeviceIdentifier());

        $limiter = \Mockery::mock(AttemptLimiter::class);
        $limiter->shouldReceive('blocked')->once()->andReturn(42);

        app()->instance(AttemptLimiter::class, $limiter);

        $this->recordEvents([AuthenticationFailed::class]);

        $blocked = $this->sessions(self::GUARD)->switchPrincipal($session->tokens->refreshToken, $second);

        self::assertSame(FailureReason::RATE_LIMITED, $blocked->reason);
        self::assertSame(42, $blocked->retryAfter);
        self::assertSame(42, $this->recordedEvent(AuthenticationFailed::class)->retryAfter);
        self::assertSame($deviceId, $this->recordedEvent(AuthenticationFailed::class)->context->deviceId);

        $limiter = \Mockery::mock(AttemptLimiter::class);
        $limiter->shouldReceive('blocked')->once()->andReturnNull();
        $limiter->shouldReceive('recordFailure')->once()->with(\Mockery::on(static fn (AttemptSubject $subject): bool => $subject->flow === AttemptFlow::REFRESH
            && $subject->guard                                                                                                          === self::GUARD
            && $subject->identifier                                                                                                     === $deviceId
            && $subject->ip                                                                                                             === self::CLIENT_IP));

        app()->instance(AttemptLimiter::class, $limiter);

        DB::table('devices')->update(['revoked_at' => $this->now, 'revoked_reason' => 'revoked']);

        self::assertSame(FailureReason::DEVICE_REVOKED, $this->sessions(self::GUARD)->switchPrincipal($session->tokens->refreshToken, $second)->reason);
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
        $result = Auth::sessions(self::GUARD)->switchPrincipalFromRequest(ActivatableTenantMembership::query()->findOrFail($request->integer('membership')));

        return [
            'outcome' => $result === null ? 'none' : ($result->isSwitched() ? 'switched' : 'failed'),
            'reason'  => $result?->reason?->value,
            'source'  => $result?->source?->value,
            'refresh' => $result?->session?->tokens->refreshToken,
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
     * Sign the member in as its default membership.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(): SignedInSession
    {
        $session = $this->sessions(self::GUARD)->signIn('password', self::credentials('member@example.test'))->session;

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
        $switched = $this->sessions(self::GUARD)->switchPrincipal($session->tokens->refreshToken, $target)->session;

        self::assertNotNull($switched);

        return $switched;
    }

    /**
     * Assert a switch of the session to the target fails for the reason,
     * reported as a `principal_switch` failure.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $target
     * @param  ?string  $token
     * @return void
     *
     * @throws \Throwable
     */
    private function assertSwitchFails(FailureReason $reason, SignedInSession $session, Principal $target, ?string $token = null): void
    {
        $this->recordEvents([AuthenticationFailed::class]);

        $result = $this->sessions(self::GUARD)->switchPrincipal($token ?? $session->tokens->refreshToken, $target);

        self::assertTrue($result->isFailed());
        self::assertFalse($result->isSwitched());
        self::assertNull($result->session);
        self::assertSame($reason, $result->reason);
        self::assertSame(AuthenticationFlow::PRINCIPAL_SWITCH, $this->recordedEvent(AuthenticationFailed::class)->flow);
        self::assertSame($reason, $this->recordedEvent(AuthenticationFailed::class)->reason);
        self::assertTrue(Auth::guard(self::GUARD)->guest());
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
     * The stored time in the one device row's column, to the second.
     *
     * @param  string  $column
     * @return string
     */
    private function storedTime(string $column): string
    {
        $value = DB::table('devices')->value($column);

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
}
