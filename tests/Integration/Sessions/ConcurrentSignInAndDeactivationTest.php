<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\TenantAuthenticationPolicy;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Listeners\RevokeSessionsOnDeactivation;
use SineMacula\Laravel\Authentication\Listeners\RevokeSessionsOnDeletion;
use SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck;
use SineMacula\Laravel\Authentication\Sessions\RevocationWriter;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Authentication\Tenancy\TenantPolicyContext;
use SineMacula\Laravel\Authentication\Tenancy\TenantRequirement;
use Tests\Concerns\InteractsWithIsolationLevels;
use Tests\Concerns\InteractsWithRecheckedMembers;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Sessions\InterruptingFactorPolicy;
use Tests\Fixtures\Tenancy\ScriptedTenantAuthenticationPolicy;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\RecheckedMember;
use Tests\Integration\Fixtures\RecheckedMembership;
use Tests\TestCase;

/**
 * Races a sign-in, a pending session's choice of principal and a switch against
 * a deactivation or deletion of the identity, principal or tenant they admit,
 * on PostgreSQL and MySQL, each side in a process with a database connection of
 * its own: the side that writes the session pauses after its admission while
 * the other commits the change and its revocation, or the change's transaction
 * stays open while the session is written. Whatever the order, the session
 * never works once the change is undone (reactivated, restored): it is refused
 * when written, or ended by the revocation, by its second pass, or by the
 * "tokens valid after" cutoff a revocation undone in the meantime moved. A
 * subject without a cutoff, whose change is undone before the paused call
 * checks its session, is the one documented exception.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AdmissionRecheck::class)]
#[CoversClass(SessionRevocations::class)]
#[CoversClass(RevocationWriter::class)]
#[CoversClass(RevokeSessionsOnDeactivation::class)]
#[CoversClass(RevokeSessionsOnDeletion::class)]
final class ConcurrentSignInAndDeactivationTest extends TestCase
{
    use InteractsWithIsolationLevels, InteractsWithRecheckedMembers, InteractsWithSessions;

    /** @var string The guard the members sign in through. */
    private const string GUARD = 'rechecked';

    /** @var int How long either side waits for the other's signal before giving up, in seconds. */
    private const int SIGNAL_TIMEOUT_SECONDS = 10;

    /** @var string Directory the sides signal each other and report outcomes in. */
    private string $signals;

    /**
     * Skip where processes cannot share the database, freeze the clocks so both
     * processes see one moment, create the tables and register the observers.
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
        $this->createRecheckedTables();

        RecheckedMember::observe(RevokeSessionsOnDeactivation::class);
        RecheckedMember::observe(RevokeSessionsOnDeletion::class);
        RecheckedMembership::observe(RevokeSessionsOnDeactivation::class);
        RecheckedMembership::observe(RevokeSessionsOnDeletion::class);

        $this->signals = sys_get_temp_dir() . '/deactivation-race-' . bin2hex(random_bytes(8));

        mkdir($this->signals);
    }

    /**
     * Remove the signals, drop the tables and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (glob(($this->signals ?? sys_get_temp_dir() . '/none') . '/*') ?: [] as $file) {
            unlink($file);
        }

        if (isset($this->signals) && is_dir($this->signals)) {
            rmdir($this->signals);
        }

        $this->dropRecheckedTables();
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * Rows of `[the change, committed with its revocation, the undo, the
     * reason the paused sign-in is refused for]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\Tests\Integration\Fixtures\RecheckedMember, \Tests\Integration\Fixtures\RecheckedMembership, \Tests\Integration\Fixtures\ActivatableTenant): mixed, 1: \Closure(\Tests\Integration\Fixtures\RecheckedMember, \Tests\Integration\Fixtures\RecheckedMembership, \Tests\Integration\Fixtures\ActivatableTenant): mixed, 2: string}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideChanges(): iterable
    {
        yield 'identity deactivated' => [
            static fn (RecheckedMember $member): bool => $member->update(['is_active' => false]),
            static fn (RecheckedMember $member): bool => $member->update(['is_active' => true]),
            'identity_inactive',
        ];
        yield 'identity soft-deleted' => [
            static fn (RecheckedMember $member): ?bool => $member->delete(),
            static fn (RecheckedMember $member): bool => $member->restore(), // @phpstan-ignore staticMethod.dynamicCall
            'identity_unknown',
        ];
        yield 'principal deactivated' => [
            static fn (RecheckedMember $member, RecheckedMembership $membership): bool => $membership->update(['is_active' => false]),
            static fn (RecheckedMember $member, RecheckedMembership $membership): bool => $membership->update(['is_active' => true]),
            'principal_inactive',
        ];
        yield 'principal soft-deleted' => [
            static fn (RecheckedMember $member, RecheckedMembership $membership): ?bool => $membership->delete(),
            static fn (RecheckedMember $member, RecheckedMembership $membership): bool => $membership->restore(), // @phpstan-ignore staticMethod.dynamicCall
            'principal_unresolved',
        ];
        yield 'tenant deactivated' => [
            static function (RecheckedMember $member, RecheckedMembership $membership, ActivatableTenant $tenant): int {
                $tenant->update(['is_active' => false]);

                return Auth::sessions(self::GUARD)->tenantDeactivated($tenant, [$membership]);
            },
            static fn (RecheckedMember $member, RecheckedMembership $membership, ActivatableTenant $tenant): bool => $tenant->update(['is_active' => true]),
            'tenant_inactive',
        ];
    }

    /**
     * A change committed, with the revocation that finds no session, while a
     * sign-in that admitted the subject before it is paused, refuses the
     * sign-in once its session commits: the session is revoked, so once the
     * subject is reactivated or restored no session of the member stands.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  \Closure(\Tests\Integration\Fixtures\RecheckedMember, \Tests\Integration\Fixtures\RecheckedMembership, \Tests\Integration\Fixtures\ActivatableTenant): mixed  $change
     * @param  \Closure(\Tests\Integration\Fixtures\RecheckedMember, \Tests\Integration\Fixtures\RecheckedMembership, \Tests\Integration\Fixtures\ActivatableTenant): mixed  $undo
     * @param  string  $reason
     * @return void
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChanges')]
    public function testAChangeCommittedWhileASignInIsPausedRefusesIt(\Closure $change, \Closure $undo, string $reason): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $outcome = $this->race(
            fn (): array => self::described($this->pausedSignIn($member, $membership)),
            function () use ($change, $member, $membership, $tenant): void {
                $change($member, $membership, $tenant);
            },
        );

        self::assertSame(['failed', $reason], $outcome);

        $undo($member, $membership, $tenant);

        self::assertSame(0, self::standingSessions());
    }

    /**
     * A sign-in that commits while the change's transaction is still open (its
     * check reads the subject as last committed, still active) is ended by the
     * change's revocation once the change commits, at either isolation level:
     * its access token is refused and its refresh token refreshes nothing once
     * the identity is reactivated.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testASignInCommittedBeforeTheChangeCommitsIsEndedByItsRevocation(string $level): void
    {
        [$member, $membership] = $this->seedRechecked();

        $tokens = $this->race(
            fn (): array => self::tokensOf(Auth::sessions(self::GUARD)->start($member, $membership, 'sso', self::requestContext())),
            function () use ($level, $member): void {
                self::beginTransactionAt($level);

                $member->update(['is_active' => false]);
            },
            static fn () => DB::commit(),
        );

        $member->update(['is_active' => true]);

        $this->assertEnded($tokens);
    }

    /**
     * A revocation called inside the change's own transaction reads the
     * sessions before a sign-in that admitted the subject commits; once the
     * change commits, its second pass ends that session, at either isolation
     * level, PostgreSQL's REPEATABLE READ (whose snapshot hides the session
     * from the first pass) among them.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testARevocationInsideTheChangesTransactionEndsALaterSessionAtTheCommit(string $level): void
    {
        [$member, $membership] = $this->seedRechecked();

        $tokens = $this->race(
            fn (): array => self::tokensOf(Auth::sessions(self::GUARD)->start($member, $membership, 'sso', self::requestContext())),
            function () use ($level, $member): void {
                self::beginTransactionAt($level);

                RecheckedMember::query()->whereKey($member->getKey())->update(['is_active' => false]);

                self::assertSame(0, Auth::sessions(self::GUARD)->identityDeactivated($member));
            },
            static fn () => DB::commit(),
        );

        RecheckedMember::query()->whereKey($member->getKey())->update(['is_active' => true]);

        $this->assertEnded($tokens);
    }

    /**
     * A deactivation, its revocation and a reactivation that all commit while a
     * sign-in is paused after its admission leave the subject active, but the
     * revocation moved the identity's "tokens valid after" cutoff past the
     * second the sign-in began, so its session is refused all the same.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeUndoneWhileASignInIsPausedRefusesItThroughTheCutoff(): void
    {
        [$member, $membership] = $this->seedRechecked();

        $outcome = $this->race(
            fn (): array => self::described($this->pausedSignIn($member, $membership)),
            function () use ($member): void {
                $this->freezeAt(CarbonImmutable::now()->addSecond());

                $member->update(['is_active' => false]);
                $member->update(['is_active' => true]);
            },
        );

        self::assertSame(['failed', 'issued_before_cutoff'], $outcome);
        self::assertSame(0, self::standingSessions());
    }

    /**
     * The documented exception: an identity that records no "tokens valid
     * after" cutoff, deactivated, revoked and reactivated while a sign-in is
     * paused after admitting it, leaves no trace for the sign-in's check, so
     * its session stands.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeUndoneWhileASignInIsPausedLeavesASubjectWithoutACutoffSignedIn(): void
    {
        $identity = $this->seedIdentity();

        $outcome = $this->race(
            function () use ($identity): array {
                app()->instance(AdditionalFactorPolicy::class, new InterruptingFactorPolicy($this->pause(...)));

                return self::described(Auth::sessions('api')->start($identity, null, 'sso', self::requestContext()));
            },
            function () use ($identity): void {
                $this->freezeAt(CarbonImmutable::now()->addSecond());

                IntegrationIdentity::query()->whereKey($identity->getKey())->update(['is_active' => false]);

                Auth::sessions('api')->identityDeactivated($identity);

                IntegrationIdentity::query()->whereKey($identity->getKey())->update(['is_active' => true]);
            },
        );

        self::assertSame(['signed_in', null], $outcome);
        self::assertSame(1, self::standingSessions());
    }

    /**
     * A pending session's choice of a principal whose tenant is deactivated,
     * with the revocation that finds no session acting in it, while the choice
     * is paused after admitting it, is refused, and its pending session ended.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeCommittedWhileAChoiceIsPausedRefusesIt(): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $other   = RecheckedMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey(), 'is_active' => true]);
        $pending = Auth::sessions(self::GUARD)->start($member, null, 'sso', self::requestContext());

        self::assertNotNull($pending->credential);
        self::assertCount(2, $pending->pending->principals ?? []);

        $credential = $pending->credential->reveal();

        $outcome = $this->race(
            function () use ($credential, $membership): array {
                app()->instance(AdditionalFactorPolicy::class, new InterruptingFactorPolicy($this->pause(...)));

                return self::described(Auth::sessions(self::GUARD)->choose($credential, $membership, self::requestClient()));
            },
            static function () use ($tenant, $membership, $other): void {
                $tenant->update(['is_active' => false]);

                Auth::sessions(self::GUARD)->tenantDeactivated($tenant, [$membership, $other]);
            },
        );

        self::assertSame(['failed', 'tenant_inactive'], $outcome);

        $tenant->update(['is_active' => true]);

        self::assertSame(0, self::standingSessions());
    }

    /**
     * A switch to a principal deactivated, with the revocation that finds no
     * session acting as it, while the switch is paused after admitting it, is
     * refused, and the session ended.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChangeCommittedWhileASwitchIsPausedRefusesIt(): void
    {
        [$member, $membership, $tenant] = $this->seedRechecked();

        $destination = RecheckedMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey(), 'is_active' => true]);
        $session     = Auth::sessions(self::GUARD)->start($member, $membership, 'sso', self::requestContext())->session;

        self::assertNotNull($session);

        $token = (string) $session->tokens->refreshToken?->reveal();

        $outcome = $this->race(
            function () use ($token, $destination): array {
                $policy = new ScriptedTenantAuthenticationPolicy;

                $policy->answer = function (TenantPolicyContext $context): TenantRequirement {
                    $this->pause();

                    return new TenantRequirement;
                };

                app()->instance(TenantAuthenticationPolicy::class, $policy);

                $result = Auth::sessions(self::GUARD)->switchTo(PresentedRefreshToken::fromBody($token), SwitchTarget::principal($destination), self::requestClient());

                return [$result->isFailed() ? 'failed' : 'switched', $result->reason?->value];
            },
            static function () use ($destination): void {
                $destination->update(['is_active' => false]);
            },
        );

        self::assertSame(['failed', 'principal_inactive'], $outcome);

        $destination->update(['is_active' => true]);

        self::assertSame(0, self::standingSessions());
    }

    /**
     * Register the guards: the members' as the default, which the observers
     * revoke through.
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
        self::configureRecheckedGuard($config);

        $config->set('auth.defaults.guard', self::GUARD);
    }

    /**
     * Start the member's session as the membership, pausing after its
     * admission, before its session is written, until the other side has made
     * its change.
     *
     * @param  \Tests\Integration\Fixtures\RecheckedMember  $member
     * @param  \Tests\Integration\Fixtures\RecheckedMembership  $membership
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function pausedSignIn(RecheckedMember $member, RecheckedMembership $membership): SignInResult
    {
        app()->instance(AdditionalFactorPolicy::class, new InterruptingFactorPolicy($this->pause(...)));

        return Auth::sessions(self::GUARD)->start($member, $membership, 'sso', self::requestContext());
    }

    /**
     * In the forked side: say it has been admitted, and wait for the other side
     * to have made its change.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    private function pause(): void
    {
        touch("{$this->signals}/admitted");

        if (self::wasSignalled("{$this->signals}/changed")) {
            return;
        }

        throw new \RuntimeException('The change was never made.');
    }

    /**
     * Race the forked side's call against the change: the forked side runs the
     * call, pausing where it pauses (or not at all); this side makes the change
     * once the forked side has paused or, for a call that never pauses, makes
     * it first and lets the call run while it is still open, then finishes it
     * once the call has returned. Returns what the forked side reported.
     *
     * @param  \Closure(): mixed  $call
     * @param  \Closure(): void  $change
     * @param  ?\Closure(): mixed  $finish
     * @return mixed
     *
     * @throws \Throwable
     */
    private function race(\Closure $call, \Closure $change, ?\Closure $finish = null): mixed
    {
        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid < 0) {
            self::fail('The forked side could not be forked.');
        }

        if ($pid === 0) {
            $this->runInChild($call, $finish === null);
        }

        if ($finish === null && !self::wasSignalled("{$this->signals}/admitted")) {
            self::abandon($pid, 'The forked side never paused after its admission.');
        }

        $change();

        touch("{$this->signals}/changed");

        if ($finish !== null && !self::wasSignalled("{$this->signals}/outcome")) {
            self::abandon($pid, 'The forked side never wrote its session while the change was open.');
        }

        if ($finish !== null) {
            $finish();
        }

        pcntl_waitpid($pid, $status);

        $reported = json_decode((string) file_get_contents("{$this->signals}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($reported);
        self::assertArrayNotHasKey('error', $reported, (string) json_encode($reported));

        return $reported['result'];
    }

    /**
     * In the forked process: wait for the change when the call does not pause
     * for it, run the call on a connection of its own, report its outcome, and
     * end without running the parent's shutdown.
     *
     * @param  \Closure(): mixed  $call
     * @param  bool  $pauses
     * @return never
     */
    private function runInChild(\Closure $call, bool $pauses): never
    {
        $outcome = ['error' => 'The other side never made its change.'];

        try {
            if ($pauses || self::wasSignalled("{$this->signals}/changed")) {
                $outcome = ['result' => $call()];
            }
        } catch (\Throwable $e) {
            $outcome = ['error' => $e::class . ': ' . $e->getMessage()];
        }

        file_put_contents("{$this->signals}/outcome.tmp", json_encode($outcome));
        rename("{$this->signals}/outcome.tmp", "{$this->signals}/outcome");

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * Assert the session the tokens belong to is ended: its access token is
     * refused on a request and its refresh token refreshes nothing.
     *
     * @param  mixed  $tokens
     * @return void
     *
     * @throws \Throwable
     */
    private function assertEnded(mixed $tokens): void
    {
        self::assertIsArray($tokens);
        self::assertIsString($tokens['access'] ?? null);
        self::assertIsString($tokens['refresh'] ?? null);

        $guard = app('auth')->guard(self::GUARD);

        self::assertInstanceOf(JwtGuard::class, $guard);

        $guard->setRequest(Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $tokens['access']]));

        self::assertNull($guard->user());
        self::assertSame('session_revoked', Auth::sessions(self::GUARD)->refresh(PresentedRefreshToken::fromBody($tokens['refresh']), self::requestClient())->reason?->value);
        self::assertSame(0, self::standingSessions());
    }

    /**
     * The result as its status and reason.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @return array{0: string, 1: ?string}
     */
    private static function described(SignInResult $result): array
    {
        return [$result->status->value, $result->reason?->value];
    }

    /**
     * The pair of a sign-in that started a session.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @return array{access: string, refresh: ?string}
     */
    private static function tokensOf(SignInResult $result): array
    {
        $session = $result->session;

        self::assertInstanceOf(SignedInSession::class, $session);

        return ['access' => $session->tokens->accessToken->reveal(), 'refresh' => $session->tokens->refreshToken?->reveal()];
    }

    /**
     * How many sessions stand: not revoked.
     *
     * @return int
     */
    private static function standingSessions(): int
    {
        return DB::table('authentication_sessions')->whereNull('revoked_at')->count();
    }

    /**
     * Wait for the other side to create the signal file, for no longer than the
     * timeout: whether it did.
     *
     * @param  string  $signal
     * @return bool
     */
    private static function wasSignalled(string $signal): bool
    {
        $deadline = microtime(true) + self::SIGNAL_TIMEOUT_SECONDS;

        while (!is_file($signal) && microtime(true) < $deadline) {
            usleep(5000);
        }

        return is_file($signal);
    }

    /**
     * Fail the race that was never set up: roll back any transaction this side
     * holds and stop and reap the forked side, so neither is left holding locks
     * on the tables the teardown drops. The pid is the forked child's, never a
     * failed fork's `-1`, which `posix_kill()` would send to every process the
     * user may signal.
     *
     * @param  positive-int  $pid
     * @param  string  $message
     * @return never
     */
    private static function abandon(int $pid, string $message): never
    {
        while (DB::transactionLevel() > 0) {
            DB::rollBack();
        }

        posix_kill($pid, SIGKILL);
        pcntl_waitpid($pid, $status);

        self::fail($message);
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
