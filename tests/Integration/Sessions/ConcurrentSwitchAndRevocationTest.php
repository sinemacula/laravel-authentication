<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\PrincipalSwitched;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Sessions\DeviceRevocations;
use SineMacula\Laravel\Authentication\Sessions\PrincipalSwitch;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SwitchResult;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * Races a switch of principal and the revocation of a device against each other
 * and against a refresh, on PostgreSQL and MySQL, each side in a process with a
 * database connection of its own: one side writes the device inside a
 * transaction it holds open, and the other, started meanwhile, waits on the
 * device's row. When the first commits, the second finds the row it read
 * changed under it and is answered from the row as it now is; when the first
 * rolls back, the second goes ahead as if alone. Either way each change is
 * made, and reported, once.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PrincipalSwitch::class)]
#[CoversClass(DeviceRevocations::class)]
final class ConcurrentSwitchAndRevocationTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string Guard over `ActivatableTenantMember`. */
    private const string GUARD = 'members';

    /** @var int How long the first side holds its transaction open once the second has started, in microseconds. */
    private const int HOLD_MICROSECONDS = 1000000;

    /** @var float The least time, in seconds, the second side must have waited to show it waited on the first. */
    private const float LEAST_WAIT_SECONDS = 0.5;

    /** @var int How long the second side waits to be started before giving up, in seconds. */
    private const int START_TIMEOUT_SECONDS = 10;

    /** @var list<class-string> The events both sides record. */
    private const array EVENTS = [DeviceRevoked::class, PrincipalSwitched::class, Refreshed::class, SignedOutEverywhere::class];

    /** @var string Directory the second side reports its outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, freeze the clocks so both
     * processes see one moment, and create the tables.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection()->getDriverName() === 'sqlite' || !function_exists('pcntl_fork')) {
            self::markTestSkipped('Racing processes need a shared database server and pcntl.');
        }

        $this->freezeAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->createSessionTables();

        $this->outcomes = sys_get_temp_dir() . '/session-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove the outcomes, drop the tables and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (glob(($this->outcomes ?? sys_get_temp_dir() . '/none') . '/*') ?: [] as $file) {
            unlink($file);
        }

        if (isset($this->outcomes) && is_dir($this->outcomes)) {
            rmdir($this->outcomes);
        }

        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * Two revocations of an identity's devices: the one that waited finds them
     * revoked once the first commits, and revokes and reports none of them; it
     * revokes and reports them itself when the first rolls back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoConcurrentRevocationsReportEachDeviceOnce(): void
    {
        foreach ([true, false] as $commit) {

            [$member] = $this->seedMemberships();

            $this->signIn();
            $this->signIn();

            [$first, $second] = $this->race(
                fn (): int => $this->sessions(self::GUARD)->revokeDevices($member, RevocationReason::REVOKED),
                fn (): int => $this->sessions(self::GUARD)->revokeDevices($member, RevocationReason::REVOKED),
                $commit,
            );

            self::assertSame(2, $first);

            if ($commit) {
                self::assertSame([DeviceRevoked::class, DeviceRevoked::class, SignedOutEverywhere::class], $this->recordedClasses());
                self::assertSame(0, $second['result']);
                self::assertSame([SignedOutEverywhere::class], $second['events']);
            } else {
                self::assertSame([], $this->recordedClasses());
                self::assertSame(2, $second['result']);
                self::assertSame([DeviceRevoked::class, DeviceRevoked::class, SignedOutEverywhere::class], $second['events']);
            }

            self::assertSame(2, DB::table('devices')->where('revoked_reason', 'revoked')->count());

            $this->reset();
        }
    }

    /**
     * A switch waiting on a revocation of its device fails as `device_revoked`
     * once the revocation commits, leaving the device revoked and unswitched;
     * when the revocation rolls back, the switch goes ahead.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchWaitingOnARevocationFollowsItsOutcome(): void
    {
        foreach ([true, false] as $commit) {

            [$member, $first, $target] = $this->seedMemberships();

            $session = $this->signIn();

            [, $second] = $this->race(
                fn (): int => $this->sessions(self::GUARD)->revokeDevices($member, RevocationReason::REVOKED),
                fn (): array => self::describe($this->sessions(self::GUARD)->switchPrincipal($session->tokens->refreshToken, $target)),
                $commit,
            );

            $row = DB::table('devices')->sole();

            if ($commit) {
                self::assertSame(['switched' => false, 'reason' => FailureReason::DEVICE_REVOKED->value], $second['result']);
                self::assertSame([], $second['events']);
                self::assertSame('revoked', $row->revoked_reason);
                self::assertSame(IdentifierCoercion::stringify($first->getKey()), IdentifierCoercion::stringify($row->principal_id));
            } else {
                self::assertSame(['switched' => true, 'reason' => null], $second['result']);
                self::assertSame([PrincipalSwitched::class], $second['events']);
                self::assertNull($row->revoked_at);
                self::assertSame(IdentifierCoercion::stringify($target->getKey()), IdentifierCoercion::stringify($row->principal_id));
            }

            $this->reset();
        }
    }

    /**
     * A switch waiting on a refresh of the same token is a conflict once the
     * refresh commits, leaving the refresh's rotation and the principal as they
     * were; when the refresh rolls back, the switch goes ahead.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchWaitingOnARefreshOfItsTokenFollowsItsOutcome(): void
    {
        foreach ([true, false] as $commit) {

            [, $first, $target] = $this->seedMemberships();

            $session = $this->signIn();

            [$refreshed, $second] = $this->race(
                fn (): bool => self::sessionsOf($this->freshGuard(self::GUARD))->refresh($session->tokens->refreshToken)->isRefreshed(),
                fn (): array => self::describe($this->sessions(self::GUARD)->switchPrincipal($session->tokens->refreshToken, $target)),
                $commit,
            );

            self::assertTrue($refreshed);

            $row = DB::table('devices')->sole();

            if ($commit) {
                self::assertSame([Refreshed::class], $this->recordedClasses());
                self::assertSame(['switched' => false, 'reason' => FailureReason::ROTATION_CONFLICT->value], $second['result']);
                self::assertSame([], $second['events']);
                self::assertSame(IdentifierCoercion::stringify($first->getKey()), IdentifierCoercion::stringify($row->principal_id));
            } else {
                self::assertSame([], $this->recordedClasses());
                self::assertSame(['switched' => true, 'reason' => null], $second['result']);
                self::assertSame([PrincipalSwitched::class], $second['events']);
                self::assertSame(IdentifierCoercion::stringify($target->getKey()), IdentifierCoercion::stringify($row->principal_id));
            }

            self::assertNull($row->revoked_at);

            $this->reset();
        }
    }

    /**
     * Two identical switches of one token: the one that waited is answered with
     * the switch the first committed, which is reported once; when the first
     * rolls back, the second makes the switch and reports it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoConcurrentIdenticalSwitchesReportTheSwitchOnce(): void
    {
        foreach ([true, false] as $commit) {

            [, , $target] = $this->seedMemberships();

            $session = $this->signIn();

            [$first, $second] = $this->race(
                fn (): array => self::describe($this->sessions(self::GUARD)->switchPrincipal($session->tokens->refreshToken, $target)),
                fn (): array => self::describe($this->sessions(self::GUARD)->switchPrincipal($session->tokens->refreshToken, $target)),
                $commit,
            );

            self::assertSame(['switched' => true, 'reason' => null], $first);
            self::assertSame(['switched' => true, 'reason' => null], $second['result']);

            if ($commit) {
                self::assertSame([PrincipalSwitched::class], $this->recordedClasses());
                self::assertSame([], $second['events']);
            } else {
                self::assertSame([], $this->recordedClasses());
                self::assertSame([PrincipalSwitched::class], $second['events']);
            }

            self::assertSame(IdentifierCoercion::stringify($target->getKey()), IdentifierCoercion::stringify(DB::table('devices')->value('principal_id')));

            $this->reset();
        }
    }

    /**
     * Register the guards.
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
     * Persist a member with its default membership and a second one, each in
     * its own active tenant.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return array{0: \Tests\Integration\Fixtures\ActivatableTenantMember, 1: \Tests\Integration\Fixtures\ActivatableTenantMembership, 2: \Tests\Integration\Fixtures\ActivatableTenantMembership}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function seedMemberships(): array
    {
        [$member, $first] = $this->seedMember();

        $other = ActivatableTenant::query()->create(['name' => 'Other', 'is_active' => true]);

        return [$member, $first, ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $other->getKey()])];
    }

    /**
     * Sign the member in as its default membership, then move the clocks on, so
     * a switch or a refresh of the session is never in its first second.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(): SignedInSession
    {
        $session = $this->sessions(self::GUARD)->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);

        $this->freezeAt(CarbonImmutable::now()->addSeconds(5));

        return $session;
    }

    /**
     * Run the first side here inside a transaction, start the second in another
     * process once the first has written, hold the transaction open while the
     * second waits on it, then commit or roll back, and return both outcomes.
     *
     * @template TFirst
     *
     * @param  \Closure(): TFirst  $first
     * @param  \Closure(): mixed  $second
     * @param  bool  $commit
     * @return array{0: TFirst, 1: array{result: mixed, events: list<string>, waited: float}}
     *
     * @throws \Throwable
     */
    private function race(\Closure $first, \Closure $second, bool $commit): array
    {
        $this->recordEvents(self::EVENTS);

        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid === 0) {
            $this->runInChild($second);
        }

        DB::beginTransaction();

        $outcome = $first();

        touch("{$this->outcomes}/start");
        usleep(self::HOLD_MICROSECONDS);

        $commit ? DB::commit() : DB::rollBack();

        pcntl_waitpid($pid, $status);

        $reported = json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($reported);
        self::assertArrayNotHasKey('error', $reported);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $reported['waited']);

        /** @var array{result: mixed, events: list<string>, waited: float} $reported */
        return [$outcome, $reported];
    }

    /**
     * In the forked process: wait to be started, run the second side on a
     * connection of its own, report its outcome, and end without running the
     * parent's shutdown.
     *
     * @param  \Closure(): mixed  $second
     * @return never
     */
    private function runInChild(\Closure $second): never
    {
        try {
            $deadline = microtime(true) + self::START_TIMEOUT_SECONDS;

            while (!is_file("{$this->outcomes}/start") && microtime(true) < $deadline) {
                usleep(5000);
            }

            $started = microtime(true);
            $result  = $second();
            $outcome = ['result' => $result, 'events' => $this->recordedClasses(), 'waited' => microtime(true) - $started];
        } catch (\Throwable $e) {
            $outcome = ['error' => $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/outcome", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * Clear the rows and the outcome a race left, for the next one.
     *
     * @return void
     */
    private function reset(): void
    {
        foreach (['devices', 'pending_sign_ins', 'rate_limits', 'activatable_tenant_memberships', 'activatable_tenants'] as $table) {
            DB::table($table)->delete();
        }

        ActivatableTenantMember::query()->delete();

        unlink("{$this->outcomes}/start");
        unlink("{$this->outcomes}/outcome");
    }

    /**
     * Whether a switch went through, and why not.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SwitchResult  $result
     * @return array{switched: bool, reason: ?string}
     */
    private static function describe(SwitchResult $result): array
    {
        return ['switched' => $result->isSwitched(), 'reason' => $result->reason?->value];
    }

    /**
     * Freeze every clock at the time.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    private function freezeAt(CarbonImmutable $time): void
    {
        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }
}
