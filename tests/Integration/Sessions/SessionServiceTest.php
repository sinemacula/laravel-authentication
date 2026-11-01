<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Login;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\DeviceCreated;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Sessions\DeviceProof;
use SineMacula\Laravel\Authentication\Sessions\DeviceSummary;
use SineMacula\Laravel\Authentication\Sessions\SessionEstablishment;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionWriter;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;
use Tests\Unit\Stubs\StubFixedPrincipalResolver;

/**
 * End-to-end tests for sessions the session service starts, against a real
 * database on whichever engine the suite runs on: the tokens work through the
 * `auth` middleware and refresh, a client that proves it holds a device has it
 * replaced when it signs in again (and only then), the session commits or rolls
 * back as one, and its lifecycle events follow the device connection's commit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(SessionEstablishment::class)]
#[CoversClass(SessionWriter::class)]
#[CoversClass(DeviceProof::class)]
#[CoversClass(SignedInSession::class)]
final class SessionServiceTest extends TestCase
{
    use InteractsWithSessions;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks, create the tables, and add a route behind the `auth`
     * middleware.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freezeClocksAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();

        Route::middleware('auth:api')->get('/me', static fn (): array => [
            'identity' => Auth::identity()?->getAuthIdentifier(),
            'device'   => Auth::device()?->getDeviceIdentifier(),
        ]);
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
     * The access token of a new session authenticates a request through the
     * `auth` middleware with its device, and its refresh token refreshes.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheFirstPairAuthenticatesAndRefreshes(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn();

        $this->bearer($session->tokens->accessToken)
            ->assertOk()
            ->assertJson(['identity' => $identity->getKey(), 'device' => $session->device->getKey()]);

        $refreshed = self::sessionsOf($this->freshGuard())->refresh($session->tokens->refreshToken)->session?->tokens;

        self::assertNotNull($refreshed);
        $this->bearer($refreshed->accessToken)->assertOk();
    }

    /**
     * A client that signs in again with its current refresh token gets a new
     * device, and the proven one is revoked as `superseded`, both digests
     * forgotten: a new key and rotation id, both deadlines from the sign-in,
     * the method and the client's new name recorded, its platform inherited
     * when it gives none, and the client it came from as the creation. The
     * replacement is reported in order, and the old refresh token is refused as
     * revoked without touching the new device.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningInAgainWithTheCurrentRefreshTokenReplacesTheDevice(): void
    {
        $this->seedIdentity();

        $first = $this->signIn(clientName: 'Laptop', platform: 'macOS');

        $rotated = self::sessionsOf($this->freshGuard())->refresh($first->tokens->refreshToken)->session?->tokens;

        self::assertNotNull($rotated);

        $current = self::sessionsOf($this->freshGuard())->refresh($rotated->refreshToken)->session?->tokens;

        self::assertNotNull($current);

        $this->advance(10 * 86400);

        $this->recordEvents([DeviceRevoked::class, DeviceCreated::class, SignedIn::class]);

        $again = $this->signIn(refreshToken: $current->refreshToken, clientName: 'Renamed laptop', method: 'sso');

        self::assertNotSame($first->device->getKey(), $again->device->getKey());
        self::assertSame([DeviceRevoked::class, DeviceCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame(RevocationReason::SUPERSEDED, $this->recordedEvent(DeviceRevoked::class)->reason);
        self::assertSame(IdentifierCoercion::stringify($first->device->getKey()), $this->recordedEvent(DeviceRevoked::class)->context->deviceId);
        self::assertSame(IdentifierCoercion::stringify($again->device->getKey()), $this->recordedEvent(DeviceCreated::class)->context->deviceId);
        self::assertSame(IdentifierCoercion::stringify($again->device->getKey()), $this->recordedEvent(SignedIn::class)->context->deviceId);

        $previous = Device::query()->whereKey($first->device->getKey())->firstOrFail();

        self::assertSame(Carbon::now()->getTimestamp(), $previous->getRevokedAt()?->getTimestamp());
        self::assertSame('superseded', $previous->getRevokedReason());
        self::assertNull($previous->getRefreshKey());
        self::assertNull($previous->getPreviousRefreshKey());
        self::assertSame('password', $previous->getSignInMethod());

        $device = Device::query()->whereKey($again->device->getKey())->firstOrFail();
        $claims = Auth::manager()->jwt('api')->parse($again->tokens->refreshToken);

        self::assertIsString($claims['jti'] ?? null);
        self::assertTrue(RefreshTokenHasher::verify($claims['jti'], (string) $device->getRefreshKey()));
        self::assertNull($device->getPreviousRefreshKey());
        self::assertNull($device->getRefreshRotatedAt());
        self::assertNull($device->getRevokedAt());
        self::assertSame(Carbon::now()->getTimestamp(), $device->getSignedInAt()?->getTimestamp());
        self::assertSame(Carbon::now()->addDays(30)->getTimestamp(), $device->getIdleExpiresAt()?->getTimestamp());
        self::assertSame(Carbon::now()->addDays(180)->getTimestamp(), $device->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertSame('sso', $device->getSignInMethod());
        self::assertSame('Renamed laptop', $device->client_name);
        self::assertSame('macOS', $device->platform);
        self::assertSame('api', $device->getGuard());
        self::assertSame(self::CLIENT_IP, $device->created_ip);
        self::assertSame(Carbon::now()->getTimestamp(), $device->getLastUsedAt()?->getTimestamp());
        self::assertSame(2, Device::query()->count());

        $this->bearer($again->tokens->accessToken)->assertOk()->assertJson(['device' => $device->getKey()]);

        $refused = self::sessionsOf($this->freshGuard())->refresh($current->refreshToken);

        self::assertSame(FailureReason::DEVICE_REVOKED, $refused->reason);
        self::assertNull(Device::query()->whereKey($device->getKey())->firstOrFail()->getRevokedAt());
        self::assertSame('superseded', Device::query()->whereKey($first->device->getKey())->firstOrFail()->getRevokedReason());
    }

    /**
     * The replaced session ends at once: its access token, still within its
     * lifetime, is refused by `auth:api`, its refresh token is refused as
     * revoked, and only the new session is listed. The new session's refresh
     * keeps its device.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReplacedSessionsTokensStopWorkingAtOnce(): void
    {
        $identity = $this->seedIdentity();

        $first = $this->signIn();

        $this->bearer($first->tokens->accessToken)->assertOk()->assertJson(['device' => $first->device->getKey()]);

        $again = $this->signIn(refreshToken: $first->tokens->refreshToken);

        $this->bearer($first->tokens->accessToken)->assertUnauthorized();
        $this->bearer($again->tokens->accessToken)->assertOk()->assertJson(['device' => $again->device->getKey()]);

        self::assertSame(FailureReason::DEVICE_REVOKED, self::sessionsOf($this->freshGuard())->refresh($first->tokens->refreshToken)->reason);
        $listed = Auth::sessions('api')->devices($identity)->items();

        self::assertSame([IdentifierCoercion::stringify($again->device->getKey())], array_map(static fn (DeviceSummary $summary): string => $summary->id, $listed));

        $refreshed = self::sessionsOf($this->freshGuard())->refresh($again->tokens->refreshToken)->session;

        self::assertSame($again->device->getKey(), $refreshed?->device->getKey());
    }

    /**
     * Signing in twice from the same IP address and user agent, without the
     * refresh token, starts two sessions and revokes nothing: only the device
     * key counts.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningInAgainWithoutAProofRevokesNothing(): void
    {
        $this->seedIdentity();

        $first = $this->signIn(clientName: 'Laptop', platform: 'macOS');

        $this->recordEvents([DeviceRevoked::class]);

        $again = $this->signIn(clientName: 'Laptop', platform: 'macOS');

        self::assertNotSame($first->device->getKey(), $again->device->getKey());
        self::assertSame(2, Device::query()->whereNull('revoked_at')->count());
        self::assertSame([], $this->recordedClasses());
        $this->bearer($first->tokens->accessToken)->assertOk();
        $this->bearer($again->tokens->accessToken)->assertOk();
    }

    /**
     * The proof may have expired, and so may the session: a client signing in
     * again after its session ended replaces its device, which is revoked even
     * though it had already expired.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExpiredRefreshTokenStillProvesTheDevice(): void
    {
        $this->seedIdentity();

        $first = $this->signIn();

        $this->advance(200 * 86400);

        self::assertNull(self::sessionsOf($this->freshGuard())->refresh($first->tokens->refreshToken)->session);

        $again = $this->signIn(refreshToken: $first->tokens->refreshToken);

        self::assertNotSame($first->device->getKey(), $again->device->getKey());
        self::assertSame('superseded', Device::query()->whereKey($first->device->getKey())->firstOrFail()->getRevokedReason());
        $this->bearer($again->tokens->accessToken)->assertOk();
    }

    /**
     * Only the current rotation id proves a device: a refresh token the device
     * has rotated past, whether just before or long before, gets a new device,
     * and the old one is left as it is, not revoked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARotatedRefreshTokenProvesNothing(): void
    {
        $this->seedIdentity();

        $first     = $this->signIn();
        $refreshed = self::sessionsOf($this->freshGuard())->refresh($first->tokens->refreshToken)->session?->tokens;

        self::assertNotNull($refreshed);

        $previous = $this->signIn(refreshToken: $first->tokens->refreshToken);

        $this->advance(3600);

        self::sessionsOf($this->freshGuard())->refresh($refreshed->refreshToken);

        $older = $this->signIn(refreshToken: $first->tokens->refreshToken);

        self::assertNotSame($first->device->getKey(), $previous->device->getKey());
        self::assertNotSame($first->device->getKey(), $older->device->getKey());
        self::assertSame(3, Device::query()->whereNull('revoked_at')->count());
    }

    /**
     * A revoked device is never replaced, whatever its refresh token says:
     * revocation is final, and the revocation keeps its own time and reason.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevokedDeviceIsNeverReplaced(): void
    {
        $this->seedIdentity();

        $first = $this->signIn();

        Device::query()->whereKey($first->device->getKey())->update(['revoked_at' => Carbon::now(), 'revoked_reason' => 'revoked']);

        $before = (array) DB::table('devices')->where('id', $first->device->getKey())->first();

        self::assertNotSame($first->device->getKey(), $this->signIn(refreshToken: $first->tokens->refreshToken)->device->getKey());
        self::assertSame($before, (array) DB::table('devices')->where('id', $first->device->getKey())->first());
    }

    /**
     * A refresh token proves a device only for its own owner, guard and
     * principal: another identity, another guard (by its token's `grd`, or by
     * the guard the device records), or another principal of the same identity
     * gets a device of its own, and the proven device is untouched; only the
     * same principal replaces it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshTokenProvesADeviceOnlyForItsOwnerGuardAndPrincipal(): void
    {
        $this->seedIdentity();
        $this->seedIdentity('bea@example.test');

        $ada = $this->signIn();
        $row = (array) DB::table('devices')->where('id', $ada->device->getKey())->first();

        self::assertNotSame($ada->device->getKey(), $this->signIn('bea@example.test', refreshToken: $ada->tokens->refreshToken)->device->getKey());
        self::assertNotSame($ada->device->getKey(), $this->signIn(guard: 'admin', refreshToken: $ada->tokens->refreshToken)->device->getKey());
        self::assertSame($row, (array) DB::table('devices')->where('id', $ada->device->getKey())->first());

        $admin = $this->signIn(guard: 'admin');

        Device::query()->whereKey($admin->device->getKey())->update(['guard' => 'api']);

        $this->signIn(guard: 'admin', refreshToken: $admin->tokens->refreshToken);

        self::assertNull(Device::query()->whereKey($admin->device->getKey())->firstOrFail()->getRevokedAt());

        [$member, $first, $tenant] = $this->seedMember();

        $second  = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        $session = $this->signIn('member@example.test', guard: 'members', principal: $first);
        $other   = $this->signIn('member@example.test', guard: 'members', refreshToken: $session->tokens->refreshToken, principal: $second);

        self::assertNotSame($session->device->getKey(), $other->device->getKey());
        self::assertNull(Device::query()->whereKey($session->device->getKey())->firstOrFail()->getRevokedAt());

        $same = $this->signIn('member@example.test', guard: 'members', refreshToken: $session->tokens->refreshToken, principal: $first);

        self::assertNotSame($session->device->getKey(), $same->device->getKey());
        self::assertSame('superseded', Device::query()->whereKey($session->device->getKey())->firstOrFail()->getRevokedReason());
        self::assertNull(Device::query()->whereKey($other->device->getKey())->firstOrFail()->getRevokedAt());
    }

    /**
     * Anything that is not a refresh token of the guard (garbage, an access
     * token) proves nothing, and revokes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenThatIsNotARefreshTokenProvesNothing(): void
    {
        $this->seedIdentity();

        $first = $this->signIn();

        $this->signIn(refreshToken: 'not-a-jwt');
        $this->signIn(refreshToken: $first->tokens->accessToken);

        self::assertSame(3, Device::query()->whereNull('revoked_at')->count());
    }

    /**
     * When the proven device changes before it can be replaced (here a parallel
     * refresh rotates it while the factor policy deliberates), the sign-in is
     * reconsidered without it, factor policy included, and starts on a new
     * device that records the sign-in's identifier type; the changed device is
     * left as the refresh made it, not revoked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeviceChangedBeforeItIsReplacedIsReconsideredWithoutIt(): void
    {
        $this->seedIdentity();

        $first  = $this->signIn();
        $proven = [];

        $factors = \Mockery::mock(AdditionalFactorPolicy::class);
        $factors->shouldReceive('requiresAdditionalFactor')->twice()->andReturnUsing(function (AdditionalFactorContext $context) use (&$proven, $first): bool {

            $proven[] = $context->provenDevice?->getDeviceIdentifier();

            if ($context->provenDevice !== null) {
                Device::query()->whereKey($first->device->getKey())->update(['refresh_key' => RefreshTokenHasher::hash('rotated-in-parallel')]);
            }

            return false;
        });

        app()->instance(AdditionalFactorPolicy::class, $factors);

        $again = $this->signIn(refreshToken: $first->tokens->refreshToken);

        self::assertSame([$first->device->getKey(), null], $proven);
        self::assertNotSame($first->device->getKey(), $again->device->getKey());
        self::assertSame('email', Device::query()->whereKey($again->device->getKey())->value('sign_in_identifier_type'));
        self::assertSame(RefreshTokenHasher::hash('rotated-in-parallel'), Device::query()->whereKey($first->device->getKey())->firstOrFail()->getRefreshKey());
        self::assertNull(Device::query()->whereKey($first->device->getKey())->firstOrFail()->getRevokedAt());
    }

    /**
     * Inside a caller's transaction the guard is bound at once, but
     * `DeviceCreated` and `SignedIn` wait for the commit, and a rollback
     * withdraws them with the device.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLifecycleEventsFollowTheCallersTransaction(): void
    {
        $this->seedIdentity();

        $this->recordEvents([DeviceAuthenticated::class, DeviceCreated::class, SignedIn::class]);

        DB::beginTransaction();

        $this->signIn();

        self::assertSame([DeviceAuthenticated::class], $this->recordedClasses());

        DB::commit();

        self::assertSame([DeviceAuthenticated::class, DeviceCreated::class, SignedIn::class], $this->recordedClasses());

        $this->recordEvents([DeviceAuthenticated::class, DeviceCreated::class, SignedIn::class]);

        DB::beginTransaction();

        $rolledBack = $this->signIn();

        DB::rollBack();

        self::assertSame([DeviceAuthenticated::class], $this->recordedClasses());
        self::assertNull(Device::query()->whereKey($rolledBack->device->getKey())->first());
    }

    /**
     * A failure while issuing the first pair (here a principal whose identifier
     * cannot be written into `pid`) rolls the new device back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureWhileIssuingRollsTheDeviceBack(): void
    {
        $this->seedIdentity();

        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturnNull();
        $principal->shouldReceive('getTenant')->andReturnNull();

        app()->instance(PrincipalResolver::class, new StubFixedPrincipalResolver($principal));

        try {
            $this->sessions()->signIn('password', self::credentials());
            self::fail('Expected issuing to fail.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringContainsString('`pid`', $exception->getMessage());
        }

        self::assertSame(0, Device::query()->count());
    }

    /**
     * A failure after the compare-and-swap that revokes a proven device (here
     * as the new device is inserted) rolls the revocation back with it: the
     * device stays live at the refresh key the client holds, so its current
     * refresh token still refreshes, and no new device is left.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureAfterRevokingAProvenDeviceRollsTheRevocationBack(): void
    {
        $this->seedIdentity();

        $first   = $this->signIn();
        $key     = Device::query()->whereKey($first->device->getKey())->firstOrFail()->getRefreshKey();
        $failure = new \ArrayObject(['armed' => true]);

        DB::listen(static function (QueryExecuted $query) use ($failure): void {
            if ($failure['armed'] && str_starts_with(strtolower($query->sql), 'insert into') && str_contains($query->sql, 'devices')) {
                throw new \RuntimeException('failed after the swap');
            }
        });

        try {
            $this->signIn(refreshToken: $first->tokens->refreshToken);
            self::fail('Expected the sign-in to fail after the swap.');
        } catch (\RuntimeException $exception) {
            self::assertSame('failed after the swap', $exception->getMessage());
        }

        $failure['armed'] = false;
        $device           = Device::query()->whereKey($first->device->getKey())->firstOrFail();

        self::assertSame($key, $device->getRefreshKey());
        self::assertNull($device->getRevokedAt());
        self::assertSame(1, Device::query()->count());
        self::assertNotNull(self::sessionsOf($this->freshGuard())->refresh($first->tokens->refreshToken)->session);
        self::assertNull(Device::query()->whereKey($first->device->getKey())->firstOrFail()->getRevokedAt());
    }

    /**
     * A listener that throws on a bind event fails the sign-in after the
     * session committed, but the session is reported: `DeviceCreated` and
     * `SignedIn` were dispatched before the bind.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAThrowingBindListenerStillLetsTheSessionBeReported(): void
    {
        $this->seedIdentity();

        $this->throwOnLogin();

        $this->recordEvents([DeviceCreated::class, SignedIn::class]);

        self::assertSame('listener failed', $this->failedSignIn());
        self::assertSame(1, Device::query()->count());
        self::assertSame([DeviceCreated::class, SignedIn::class], $this->recordedClasses());
    }

    /**
     * Inside a caller's transaction that catches a throwing bind listener and
     * commits, the session's events follow the commit; one that rolls back
     * withdraws them with the device.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAThrowingBindListenerInsideTheCallersTransactionFollowsItsOutcome(): void
    {
        $this->seedIdentity();

        $this->throwOnLogin();

        $this->recordEvents([DeviceCreated::class, SignedIn::class]);

        DB::beginTransaction();

        self::assertSame('listener failed', $this->failedSignIn());
        self::assertSame([], $this->recordedClasses());

        DB::commit();

        self::assertSame([DeviceCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertSame(1, Device::query()->count());

        $this->recordEvents([DeviceCreated::class, SignedIn::class]);

        DB::beginTransaction();

        self::assertSame('listener failed', $this->failedSignIn());

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertSame(1, Device::query()->count());
    }

    /**
     * A refresh whose bind listener throws is reported once its rotation
     * commits, and not at all when the caller rolls it back, which leaves the
     * device's rotation as it was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAThrowingBindListenerOnARefreshFollowsTheCallersTransaction(): void
    {
        $this->seedIdentity();

        $session = $this->signIn();
        $before  = Device::query()->whereKey($session->device->getKey())->firstOrFail()->getRefreshKey();

        $this->throwOnLogin();

        $this->recordEvents([Refreshed::class, SignedIn::class]);

        DB::beginTransaction();

        self::assertSame('listener failed', $this->failedRefresh($session->tokens->refreshToken));
        self::assertSame([], $this->recordedClasses());

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertSame($before, Device::query()->whereKey($session->device->getKey())->firstOrFail()->getRefreshKey());

        DB::beginTransaction();

        self::assertSame('listener failed', $this->failedRefresh($session->tokens->refreshToken));

        DB::commit();

        self::assertSame([Refreshed::class, SignedIn::class], $this->recordedClasses());
        self::assertNotSame($before, Device::query()->whereKey($session->device->getKey())->firstOrFail()->getRefreshKey());
    }

    /**
     * A crafted client name and platform are stored cleaned, so a sign-in
     * cannot be turned into a server error by them.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACraftedClientDescriptionIsStoredCleaned(): void
    {
        $this->seedIdentity();

        $session = $this->signIn(clientName: "Lap\0top\xFF" . str_repeat('é', 300), platform: "\0");
        $device  = Device::query()->whereKey($session->device->getKey())->firstOrFail();

        self::assertSame('Laptop?' . str_repeat('é', 248), $device->client_name);
        self::assertNull($device->platform);
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
     * Move both clocks to the time, as `travel()` moves Laravel's.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    private function freezeClocksAt(CarbonImmutable $time): void
    {
        $this->now = $time;

        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }

    /**
     * Move both clocks forward by the seconds.
     *
     * @param  int  $seconds
     * @return void
     */
    private function advance(int $seconds): void
    {
        $this->freezeClocksAt($this->now->addSeconds($seconds));
    }

    /**
     * Sign in through the session service and return the session.
     *
     * @param  string  $email
     * @param  string  $guard
     * @param  ?string  $refreshToken
     * @param  ?string  $clientName
     * @param  ?string  $platform
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  string  $method
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(
        string $email = 'ada@example.test',
        string $guard = 'api',
        #[\SensitiveParameter] ?string $refreshToken = null,
        ?string $clientName = null,
        ?string $platform = null,
        ?Principal $principal = null,
        string $method = 'password',
    ): SignedInSession {
        $sessions = $this->sessions($guard);
        $context  = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), $clientName, $platform, $principal, $refreshToken);

        $result = $method === 'password'
            ? $sessions->signIn('password', self::credentials($email), $context)
            : $sessions->start($this->identity($guard, $email), null, $method, $context);

        self::assertNotNull($result->session, 'Expected the sign-in to start a session; it failed with ' . $result->reason?->value);

        return $result->session;
    }

    /**
     * Make every `Login` listener call throw.
     *
     * @return void
     */
    private function throwOnLogin(): void
    {
        Event::listen(Login::class, static function (): never {
            throw new \RuntimeException('listener failed');
        });
    }

    /**
     * Sign in, expecting a listener to throw, and return its message.
     *
     * @return string
     *
     * @throws \Throwable
     */
    private function failedSignIn(): string
    {
        try {
            $this->sessions()->signIn('password', self::credentials());
        } catch (\RuntimeException $exception) {
            return $exception->getMessage();
        }

        self::fail('Expected the listener to throw.');
    }

    /**
     * Refresh, expecting a listener to throw, and return its message.
     *
     * @param  string  $refreshToken
     * @return string
     *
     * @throws \Throwable
     */
    private function failedRefresh(#[\SensitiveParameter] string $refreshToken): string
    {
        try {
            self::sessionsOf($this->freshGuard())->refresh($refreshToken);
        } catch (\RuntimeException $exception) {
            return $exception->getMessage();
        }

        self::fail('Expected the listener to throw.');
    }

    /**
     * Look up the identity with the email through the guard's provider.
     *
     * @param  string  $guard
     * @param  string  $email
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private function identity(string $guard, string $email): Identity
    {
        $identity = $this->freshGuard($guard)->getProvider()->retrieveByCredentials(['email' => $email]);

        self::assertInstanceOf(Identity::class, $identity);

        return $identity;
    }

    /**
     * Send a request with the bearer token to the protected route.
     *
     * @param  string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(#[\SensitiveParameter] string $token): TestResponse
    {
        return $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/me');
    }
}
