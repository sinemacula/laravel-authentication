<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\PrincipalSwitched;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Sessions\PrincipalSwitch;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SwitchResult;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * Integration tests of a switch of principal racing other writes to its device,
 * against a real database: the switch's compare-and-swap misses whenever the
 * row changed after it was read, and the row is then judged once more, under a
 * lock, without a second swap.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrincipalSwitch::class)]
#[CoversClass(RefreshRotationStore::class)]
final class PrincipalSwitchTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string Guard over `ActivatableTenantMember`. */
    private const string GUARD = 'members';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks, create the tables and register the route.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freezeAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();

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
     * A switch that loses its swap to a refresh of the same token is a
     * conflict: the refresh stands, nothing is switched and nothing revoked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchRacingARefreshIsAConflict(): void
    {
        [$first, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        $refreshed = null;

        $this->beforeTheSwap(function () use ($session, &$refreshed): void {
            $refreshed = self::sessionsOf($this->freshGuard(self::GUARD))->refresh($session->tokens->refreshToken)->session?->tokens;
        });

        $this->recordEvents([PrincipalSwitched::class, DeviceRevoked::class]);

        $result = $this->switch($session, $second);

        self::assertNotNull($refreshed);
        self::assertSame(FailureReason::ROTATION_CONFLICT, $result->reason);
        self::assertSame([], $this->recordedClasses());

        $row = DB::table('devices')->sole();

        self::assertSame((string) $first->getKey(), (string) $row->principal_id); // @phpstan-ignore cast.string
        self::assertNull($row->principal_switched_at);
        self::assertNull($row->revoked_at);
    }

    /**
     * A switch that loses its swap to a revocation of the device fails as
     * `device_revoked` and leaves the revocation in place.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchRacingARevocationFails(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->beforeTheSwap(static function (): void {
            DB::table('devices')->update(['revoked_at' => CarbonImmutable::now(), 'revoked_reason' => 'revoked', 'refresh_key' => null, 'previous_refresh_key' => null]);
        });

        self::assertSame(FailureReason::DEVICE_REVOKED, $this->switch($session, $second)->reason);
        self::assertSame('revoked', DB::table('devices')->value('revoked_reason'));
        self::assertNull(DB::table('devices')->value('principal_switched_at'));
    }

    /**
     * Two identical switches of the same token both end with the target's
     * credential: the one that loses the swap finds the switch it would have
     * made and answers with it, and the switch is reported once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoIdenticalSwitchesBothSucceedAndReportOnce(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        $winner = null;

        $this->beforeTheSwap(function () use ($session, $second, &$winner): void {
            $winner = $this->switch($session, $second);
        });

        $this->recordEvents([PrincipalSwitched::class, AuthenticationFailed::class]);

        $loser = $this->switch($session, $second);

        self::assertInstanceOf(SwitchResult::class, $winner);
        self::assertTrue($winner->isSwitched());
        self::assertTrue($loser->isSwitched());
        self::assertTrue($loser->session?->principal->is($second)); // @phpstan-ignore method.notFound
        self::assertSame([PrincipalSwitched::class], $this->recordedClasses());
        self::assertSame(IdentifierCoercion::stringify($second->getKey()), IdentifierCoercion::stringify(DB::table('devices')->value('principal_id')));
    }

    /**
     * Two switches of the same token to different principals: the first stands,
     * and the second is a conflict.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoSwitchesToDifferentPrincipalsLeaveTheFirst(): void
    {
        [, $second, $member] = $this->seedMemberships();

        $tenant = ActivatableTenant::query()->create(['name' => 'Third', 'is_active' => true]);
        $third  = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);

        $session = $this->signIn();

        $this->advance(5);

        $this->beforeTheSwap(function () use ($session, $second): void {
            self::assertTrue($this->switch($session, $second)->isSwitched());
        });

        self::assertSame(FailureReason::ROTATION_CONFLICT, $this->switch($session, $third)->reason);
        self::assertSame(IdentifierCoercion::stringify($second->getKey()), IdentifierCoercion::stringify(DB::table('devices')->value('principal_id')));
    }

    /**
     * A switch whose swap misses while its token is still the current one (the
     * deadlines moved under it) is a conflict, and one whose device was deleted
     * under it fails as `device_unknown`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwapThatMissesWithoutARotationFails(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->beforeTheSwap(function (): void {
            DB::table('devices')->update(['idle_expires_at' => $this->now->addDay()]);
        });

        self::assertSame(FailureReason::ROTATION_CONFLICT, $this->switch($session, $second)->reason);

        $this->beforeTheSwap(static function (): void {
            DB::table('devices')->delete();
        });

        self::assertSame(FailureReason::DEVICE_UNKNOWN, $this->switch($session, $second)->reason);
    }

    /**
     * A switch to the principal the session already acts as, whose swap misses
     * while its token is still the current one, is a conflict too: it is not
     * answered as a retry.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwapToTheCurrentPrincipalThatMissesIsAConflict(): void
    {
        [$first] = $this->seedMemberships();

        $session = $this->signIn();

        $this->beforeTheSwap(function (): void {
            DB::table('devices')->update(['idle_expires_at' => $this->now->addDay()]);
        });

        self::assertSame(FailureReason::ROTATION_CONFLICT, $this->switch($session, $first)->reason);
    }

    /**
     * A switch that loses its swap to the same switch, after which the device
     * passed to another identity, is refused as `identity_unknown`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALostSwapReChecksTheOwner(): void
    {
        [, $second] = $this->seedMemberships();

        [$other] = $this->seedMember('other@example.test');

        $session = $this->signIn();

        $this->advance(5);

        $this->beforeTheSwap(function () use ($session, $second, $other): void {
            self::assertTrue($this->switch($session, $second)->isSwitched());

            DB::table('devices')->update(['authenticatable_id' => IdentifierCoercion::stringify($other->getKey())]);
        });

        self::assertSame(FailureReason::IDENTITY_UNKNOWN, $this->switch($session, $second)->reason);
    }

    /**
     * A lost switch response retried after the target's tenant was deactivated
     * is refused: every live check runs on the retry too.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARetriedSwitchChecksTheTargetAgain(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        self::assertTrue($this->switch($session, $second)->isSwitched());

        ActivatableTenant::query()->whereKey($second->tenant_id)->update(['is_active' => false]);

        self::assertSame(FailureReason::TENANT_INACTIVE, $this->switch($session, $second)->reason);
        self::assertNull(DB::table('devices')->value('revoked_at'));
    }

    /**
     * A switch that loses its swap to a refresh of the same token, with the
     * grace window off, finds its token replayed when it judges the row again:
     * the device is revoked as `rotation_reuse`, as a refresh revokes it, and
     * `DeviceRevoked` is reported once the caller's transaction commits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALostSwapToARefreshWithoutAGraceWindowRevokesTheDevice(): void
    {
        config()->set('auth.guards.' . self::GUARD . '.jwt.refresh_grace_seconds', 0);

        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        $refreshed = [];

        $this->beforeTheSwap(function () use ($session, &$refreshed): void {
            $refreshed[] = self::sessionsOf($this->freshGuard(self::GUARD))->refresh($session->tokens->refreshToken)->session?->tokens;
        });

        $this->assertALostSwapRevokesTheDevice($session, $second, $refreshed);
    }

    /**
     * A switch that loses its swap to two refreshes in a row finds its token
     * two rotations old, which no grace window honours: the device is revoked
     * as `rotation_reuse`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALostSwapToTwoRotationsRevokesTheDevice(): void
    {
        [, $second] = $this->seedMemberships();

        $session = $this->signIn();

        $this->advance(5);

        $refreshed = [];

        $this->beforeTheSwap(function () use ($session, &$refreshed): void {

            $refreshed[] = $first = self::sessionsOf($this->freshGuard(self::GUARD))->refresh($session->tokens->refreshToken)->session?->tokens;

            self::assertNotNull($first);

            $refreshed[] = self::sessionsOf($this->freshGuard(self::GUARD))->refresh($first->refreshToken)->session?->tokens;
        });

        $this->assertALostSwapRevokesTheDevice($session, $second, $refreshed);
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
     * Persist a member with its default membership and a second one, each in
     * its own active tenant.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{0: \Tests\Integration\Fixtures\ActivatableTenantMembership, 1: \Tests\Integration\Fixtures\ActivatableTenantMembership, 2: \Tests\Integration\Fixtures\ActivatableTenantMember}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function seedMemberships(): array
    {
        [$member, $first] = $this->seedMember();

        $other  = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);
        $second = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()]);

        return [$first, $second, $member];
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
     * Switch the session to the target on a guard resolved afresh.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @param  \Tests\Integration\Fixtures\ActivatableTenantMembership  $target
     * @return \SineMacula\Laravel\Authentication\Sessions\SwitchResult
     *
     * @throws \Throwable
     */
    private function switch(SignedInSession $session, ActivatableTenantMembership $target): SwitchResult
    {
        return $this->sessions(self::GUARD)->switchPrincipal($session->tokens->refreshToken, $target);
    }

    /**
     * Run the switch inside a transaction and assert that, losing its swap to
     * the given refreshes, it revoked the device as a replay: `DeviceRevoked`
     * only once committed, both digests cleared, nothing switched, and every
     * token of the session refused at the `auth` middleware and by a refresh.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @param  \Tests\Integration\Fixtures\ActivatableTenantMembership  $target
     * @param  list<?\SineMacula\Laravel\Authentication\Jwt\TokenPair>  $refreshed
     * @return void
     *
     * @throws \Throwable
     */
    private function assertALostSwapRevokesTheDevice(SignedInSession $session, ActivatableTenantMembership $target, array &$refreshed): void
    {
        $this->recordEvents([PrincipalSwitched::class, DeviceRevoked::class]);

        $result = DB::transaction(function () use ($session, $target): SwitchResult {

            $result = $this->switch($session, $target);

            self::assertSame([], $this->recordedClasses());

            return $result;
        });

        self::assertSame(FailureReason::ROTATION_REUSE, $result->reason);
        self::assertSame([DeviceRevoked::class], $this->recordedClasses());
        self::assertSame(RevocationReason::ROTATION_REUSE, $this->recordedEvent(DeviceRevoked::class)->reason);

        $row = DB::table('devices')->sole();

        self::assertSame('rotation_reuse', $row->revoked_reason);
        self::assertNotNull($row->revoked_at);
        self::assertNull($row->refresh_key);
        self::assertNull($row->previous_refresh_key);
        self::assertNull($row->principal_switched_at);

        $tokens = array_map(static function (?TokenPair $tokens): TokenPair {

            self::assertNotNull($tokens);

            return $tokens;
        }, $refreshed);

        self::assertNotSame([], $tokens);

        foreach ([$session->tokens, ...$tokens] as $pair) {
            $this->bearer($pair->accessToken)->assertUnauthorized();
            self::assertNull(self::sessionsOf($this->freshGuard(self::GUARD))->refresh($pair->refreshToken)->session);
        }
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

    /**
     * Run the callback once, just before the next switch's compare-and-swap
     * executes.
     *
     * @param  \Closure(): void  $callback
     * @return void
     */
    private function beforeTheSwap(\Closure $callback): void
    {
        $done = false;

        DB::connection()->beforeExecuting(static function (string $query) use ($callback, &$done): void {

            $statement = strtolower($query);

            if ($done || !str_starts_with($statement, 'update') || !str_contains($statement, 'previous_refresh_key')) {
                return;
            }

            $done = true;

            $callback();
        });
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
