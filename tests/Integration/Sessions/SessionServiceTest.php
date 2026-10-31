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
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Sessions\DeviceProof;
use SineMacula\Laravel\Authentication\Sessions\SessionEstablishment;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SessionWriter;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;
use Tests\Unit\Stubs\StubFixedPrincipalResolver;

/**
 * End-to-end tests for sessions the session service starts, against a real
 * database on whichever engine the suite runs on: the tokens work through the
 * `auth` middleware and refresh, a client that proves it holds a device signs
 * in again on it (and only then), the session commits or rolls back as one, and
 * its lifecycle events follow the device connection's commit.
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
     * A client that signs in again with its current refresh token continues on
     * the same device: a new rotation id with no previous one, both deadlines
     * restarted, the method and the client's new name recorded, its platform
     * kept when it gives none, and the creation details kept. No
     * `DeviceCreated` is dispatched, and the old refresh token is now a replay
     * that revokes the device.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningInAgainWithTheCurrentRefreshTokenContinuesTheDevice(): void
    {
        $this->seedIdentity();

        $first = $this->signIn(clientName: 'Laptop', platform: 'macOS');

        $rotated = self::sessionsOf($this->freshGuard())->refresh($first->tokens->refreshToken)->session?->tokens;

        self::assertNotNull($rotated);

        $current = self::sessionsOf($this->freshGuard())->refresh($rotated->refreshToken)->session?->tokens;

        self::assertNotNull($current);
        self::assertNotNull(Device::query()->whereKey($first->device->getKey())->firstOrFail()->getPreviousRefreshKey());

        $this->advance(10 * 86400);

        $this->recordEvents([DeviceCreated::class, SignedIn::class]);

        $again = $this->signIn(refreshToken: $current->refreshToken, clientName: 'Renamed laptop', method: 'sso');

        self::assertSame($first->device->getKey(), $again->device->getKey());
        self::assertFalse($again->deviceCreated);
        self::assertSame([SignedIn::class], $this->recordedClasses());
        self::assertFalse($this->recordedEvent(SignedIn::class)->deviceCreated);
        self::assertFalse($this->recordedEvent(SignedIn::class)->refresh);

        $device = Device::query()->whereKey($first->device->getKey())->firstOrFail();

        self::assertNull($device->getPreviousRefreshKey());
        self::assertNull($device->getRefreshRotatedAt());
        $claims = Auth::manager()->jwt('api')->parse($again->tokens->refreshToken);

        self::assertIsString($claims['jti'] ?? null);
        self::assertTrue(RefreshTokenHasher::verify($claims['jti'], (string) $device->getRefreshKey()));
        self::assertSame(Carbon::now()->addDays(30)->getTimestamp(), $device->getIdleExpiresAt()?->getTimestamp());
        self::assertSame(Carbon::now()->addDays(180)->getTimestamp(), $device->getAbsoluteExpiresAt()?->getTimestamp());
        self::assertSame('sso', $device->getSignInMethod());
        self::assertSame('Renamed laptop', $device->client_name);
        self::assertSame('macOS', $device->platform);
        self::assertSame('api', $device->getGuard());
        self::assertSame(self::CLIENT_IP, $device->created_ip);
        self::assertSame(Carbon::now()->getTimestamp(), $device->getLastUsedAt()?->getTimestamp());
        self::assertSame(1, Device::query()->count());

        $this->bearer($again->tokens->accessToken)->assertOk()->assertJson(['device' => $device->getKey()]);

        Event::fake([DeviceRevoked::class]);

        self::assertNull(self::sessionsOf($this->freshGuard())->refresh($current->refreshToken)->session);
        self::assertNotNull(Device::query()->whereKey($device->getKey())->firstOrFail()->getRevokedAt());
        Event::assertDispatched(DeviceRevoked::class);
    }

    /**
     * The proof may have expired, and so may the session: a client signing in
     * again after its session ended continues its device, whose session starts
     * over.
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

        self::assertSame($first->device->getKey(), $again->device->getKey());
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

        self::assertTrue($previous->deviceCreated);
        self::assertTrue($older->deviceCreated);
        self::assertSame(3, Device::query()->count());
        self::assertNull(Device::query()->whereKey($first->device->getKey())->firstOrFail()->getRevokedAt());
    }

    /**
     * A revoked device is never continued, whatever its refresh token says:
     * revocation is final.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevokedDeviceIsNeverContinued(): void
    {
        $this->seedIdentity();

        $first = $this->signIn();

        Device::query()->whereKey($first->device->getKey())->update(['revoked_at' => Carbon::now()]);

        self::assertTrue($this->signIn(refreshToken: $first->tokens->refreshToken)->deviceCreated);
    }

    /**
     * A refresh token proves a device only for its own owner, guard and
     * principal: another identity, another guard (by its token's `grd`, or by
     * the guard the device records), or another principal of the same identity
     * gets a device of its own, and the proven device is untouched.
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

        self::assertTrue($this->signIn('bea@example.test', refreshToken: $ada->tokens->refreshToken)->deviceCreated);
        self::assertTrue($this->signIn(guard: 'admin', refreshToken: $ada->tokens->refreshToken)->deviceCreated);
        self::assertSame($row, (array) DB::table('devices')->where('id', $ada->device->getKey())->first());

        $admin = $this->signIn(guard: 'admin');

        Device::query()->whereKey($admin->device->getKey())->update(['guard' => 'api']);

        self::assertTrue($this->signIn(guard: 'admin', refreshToken: $admin->tokens->refreshToken)->deviceCreated);

        [$member, $first, $tenant] = $this->seedMember();

        $second  = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        $session = $this->signIn('member@example.test', guard: 'members', principal: $first);
        $other   = $this->signIn('member@example.test', guard: 'members', refreshToken: $session->tokens->refreshToken, principal: $second);
        $same    = $this->signIn('member@example.test', guard: 'members', refreshToken: $session->tokens->refreshToken, principal: $first);

        self::assertTrue($other->deviceCreated);
        self::assertFalse($same->deviceCreated);
        self::assertSame($session->device->getKey(), $same->device->getKey());
    }

    /**
     * Anything that is not a refresh token of the guard (garbage, an access
     * token) proves nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenThatIsNotARefreshTokenProvesNothing(): void
    {
        $this->seedIdentity();

        $first = $this->signIn();

        self::assertTrue($this->signIn(refreshToken: 'not-a-jwt')->deviceCreated);
        self::assertTrue($this->signIn(refreshToken: $first->tokens->accessToken)->deviceCreated);
    }

    /**
     * When the proven device changes before it can be continued (here a
     * parallel refresh rotates it while the factor policy deliberates), the
     * sign-in is reconsidered without it, factor policy included, and starts on
     * a new device that records the sign-in's identifier type; the changed
     * device is left as the refresh made it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeviceChangedBeforeItIsContinuedIsReconsideredWithoutIt(): void
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
        self::assertTrue($again->deviceCreated);
        self::assertNotSame($first->device->getKey(), $again->device->getKey());
        self::assertSame('email', Device::query()->whereKey($again->device->getKey())->value('sign_in_identifier_type'));
        self::assertSame(RefreshTokenHasher::hash('rotated-in-parallel'), Device::query()->whereKey($first->device->getKey())->firstOrFail()->getRefreshKey());
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
     * A failure after the compare-and-swap that continues a proven device (here
     * just after the device is updated) rolls the swap back with it: the device
     * keeps the refresh key the client holds, so its current refresh token
     * still refreshes instead of becoming a replay that revokes the device.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureAfterContinuingADeviceRollsTheSwapBack(): void
    {
        $this->seedIdentity();

        $first   = $this->signIn();
        $key     = Device::query()->whereKey($first->device->getKey())->firstOrFail()->getRefreshKey();
        $failure = new \ArrayObject(['armed' => true]);

        DB::listen(static function (QueryExecuted $query) use ($failure): void {
            if ($failure['armed'] && str_starts_with(strtolower($query->sql), 'update') && str_contains($query->sql, 'devices')) {
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
