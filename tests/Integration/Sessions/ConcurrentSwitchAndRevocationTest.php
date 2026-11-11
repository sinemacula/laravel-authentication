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
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\PrincipalSwitched;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Events\SteppedUp;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Sessions\AccessTokenResult;
use SineMacula\Laravel\Authentication\Sessions\ProofIssuance;
use SineMacula\Laravel\Authentication\Sessions\RevocationWriter;
use SineMacula\Laravel\Authentication\Sessions\SessionSwitch;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SwitchResult;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithIsolationLevels;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * Races switches, step-ups, revocations and refreshes of one session, each in
 * its own process.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionSwitch::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(RevocationWriter::class)]
#[CoversClass(ProofIssuance::class)]
final class ConcurrentSwitchAndRevocationTest extends TestCase
{
    use InteractsWithIsolationLevels, InteractsWithProofs, InteractsWithSessions;

    /** @var string Guard over `ActivatableTenantMember`. */
    private const string GUARD = 'members';

    /** @var string Second connection to the same database, for a change committed while a retry runs. */
    private const string COMPETITOR = 'competitor';

    /** @var int How long the first side holds its transaction open once the second has started, in microseconds. */
    private const int HOLD_MICROSECONDS = 1000000;

    /** @var float The least time, in seconds, the second side must have waited to show it waited on the first. */
    private const float LEAST_WAIT_SECONDS = 0.5;

    /** @var int How long the second side waits to be started before giving up, in seconds. */
    private const int START_TIMEOUT_SECONDS = 10;

    /** @var list<class-string> The events both sides record. */
    private const array EVENTS = [SessionRevoked::class, PrincipalSwitched::class, Refreshed::class, SignedOutEverywhere::class, SteppedUp::class];

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
     * Two concurrent revocations report each session once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoConcurrentRevocationsReportEachSessionOnce(): void
    {
        foreach ([true, false] as $commit) {

            [$member, $default] = $this->seedMemberships();

            $this->signIn($default);
            $this->signIn($default);

            [$first, $second] = $this->race(
                fn (): int => $this->sessions(self::GUARD)->revokeSessions($member, RevocationReason::REVOKED),
                fn (): int => $this->sessions(self::GUARD)->revokeSessions($member, RevocationReason::REVOKED),
                $commit,
            );

            self::assertSame(2, $first);

            if ($commit) {
                self::assertSame([SessionRevoked::class, SessionRevoked::class, SignedOutEverywhere::class], $this->recordedClasses());
                self::assertSame(0, $second['result']);
                self::assertSame([SignedOutEverywhere::class], $second['events']);
            } else {
                self::assertSame([], $this->recordedClasses());
                self::assertSame(2, $second['result']);
                self::assertSame([SessionRevoked::class, SessionRevoked::class, SignedOutEverywhere::class], $second['events']);
            }

            self::assertSame(2, DB::table('authentication_sessions')->where('revoked_reason', 'revoked')->count());

            $this->reset();
        }
    }

    /**
     * A switch waiting on a revocation follows its outcome.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchWaitingOnARevocationFollowsItsOutcome(): void
    {
        foreach ([true, false] as $commit) {

            [$member, $first, $target] = $this->seedMemberships();

            $session = $this->signIn($first);

            [, $second] = $this->race(
                fn (): int => $this->sessions(self::GUARD)->revokeSessions($member, RevocationReason::REVOKED),
                fn (): array => self::describe(
                    $this->sessions(self::GUARD)->switchTo(
                        self::bodyToken($session->tokens),
                        SwitchTarget::principal($target),
                        self::requestClient(),
                    ),
                ),
                $commit,
            );

            $row = DB::table('authentication_sessions')->sole();

            if ($commit) {
                self::assertSame(['switched' => false, 'reason' => FailureReason::SESSION_REVOKED->value], $second['result']);
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
     * A switch waiting on a refresh of its token follows its outcome.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchWaitingOnARefreshOfItsTokenFollowsItsOutcome(): void
    {
        foreach ([true, false] as $commit) {

            [, $first, $target] = $this->seedMemberships();

            $session = $this->signIn($first);

            [$refreshed, $second] = $this->race(
                fn (): bool => self::sessionsOf($this->freshGuard(self::GUARD))->refresh(
                    self::bodyToken($session->tokens),
                    self::requestClient(),
                )->isRefreshed(),
                fn (): array => self::describe(
                    $this->sessions(self::GUARD)->switchTo(
                        self::bodyToken($session->tokens),
                        SwitchTarget::principal($target),
                        self::requestClient(),
                    ),
                ),
                $commit,
            );

            self::assertTrue($refreshed);

            $row = DB::table('authentication_sessions')->sole();

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
     * Two concurrent identical switches report the switch once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoConcurrentIdenticalSwitchesReportTheSwitchOnce(): void
    {
        foreach ([true, false] as $commit) {

            [, $default, $target] = $this->seedMemberships();

            $session = $this->signIn($default);

            [$first, $second] = $this->race(
                fn (): array => self::describe(
                    $this->sessions(self::GUARD)->switchTo(
                        self::bodyToken($session->tokens),
                        SwitchTarget::principal($target),
                        self::requestClient(),
                    ),
                ),
                fn (): array => self::describe(
                    $this->sessions(self::GUARD)->switchTo(
                        self::bodyToken($session->tokens),
                        SwitchTarget::principal($target),
                        self::requestClient(),
                    ),
                ),
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

            self::assertSame(IdentifierCoercion::stringify($target->getKey()), IdentifierCoercion::stringify(DB::table('authentication_sessions')->value('principal_id')));

            $this->reset();
        }
    }

    /**
     * A revocation waits on a step-up of its session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevocationWaitsOnAStepUpOfItsSession(): void
    {
        foreach ([true, false] as $commit) {

            [$member, $first] = $this->seedMemberships();

            $session = $this->signIn($first);

            [$steppedUp, $second] = $this->race(
                fn (): array => self::stepUpOutcome(
                    $this->sessions(self::GUARD)->stepUp(self::adapterProof($member, self::GUARD, $session->record->getKey()), self::requestClient()),
                ),
                fn (): int => $this->sessions(self::GUARD)->revokeSessions($member, RevocationReason::REVOKED),
                $commit,
            );

            self::assertSame(['issued' => true, 'reason' => null], $steppedUp);
            self::assertSame(1, $second['result']);
            self::assertSame([SessionRevoked::class, SignedOutEverywhere::class], $second['events']);
            self::assertSame($commit ? [SteppedUp::class] : [], $this->recordedClasses());
            self::assertSame($commit ? 1 : 0, DB::table('authentication_proofs')->where('kind', 'additional_factor')->count());
            self::assertSame('revoked', DB::table('authentication_sessions')->sole()->revoked_reason);

            $this->reset();
        }
    }

    /**
     * A step-up waiting on a revocation follows its outcome.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStepUpWaitingOnARevocationFollowsItsOutcome(): void
    {
        foreach ([true, false] as $commit) {

            [$member, $first] = $this->seedMemberships();

            $session = $this->signIn($first);

            [$revoked, $second] = $this->race(
                fn (): int => $this->sessions(self::GUARD)->revokeSessions($member, RevocationReason::REVOKED),
                fn (): array => self::stepUpOutcome(
                    $this->sessions(self::GUARD)->stepUp(self::adapterProof($member, self::GUARD, $session->record->getKey()), self::requestClient()),
                ),
                $commit,
            );

            self::assertSame(1, $revoked);

            if ($commit) {
                self::assertSame(['issued' => false, 'reason' => FailureReason::SESSION_REVOKED->value], $second['result']);
                self::assertSame([], $second['events']);
                self::assertSame(0, DB::table('authentication_proofs')->where('kind', 'additional_factor')->count());
                self::assertSame('revoked', DB::table('authentication_sessions')->sole()->revoked_reason);
            } else {
                self::assertSame(['issued' => true, 'reason' => null], $second['result']);
                self::assertSame([SteppedUp::class], $second['events']);
                self::assertSame(1, DB::table('authentication_proofs')->where('kind', 'additional_factor')->count());
                self::assertNull(DB::table('authentication_sessions')->sole()->revoked_at);
            }

            $this->reset();
        }
    }

    /**
     * Rows of `[grace retry]`.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideGraceRetries(): iterable
    {
        yield 'refresh' => ['refresh'];
        yield 'switch' => ['switch'];
    }

    /**
     * A grace retry waiting on a revocation follows its outcome.
     *
     * @param  string  $retry
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideGraceRetries')]
    public function testAGraceRetryWaitingOnARevocationFollowsItsOutcome(string $retry): void
    {
        foreach ([true, false] as $commit) {

            [$member, $first, $target] = $this->seedMemberships();

            $session = $this->signIn($first);
            $again   = $this->graceRetryOf($retry, $session, $target);

            [$revoked, $second] = $this->race(
                fn (): int => $this->sessions(self::GUARD)->revokeSessions($member, RevocationReason::REVOKED),
                $again,
                $commit,
            );

            self::assertSame(1, $revoked);

            if ($commit) {
                self::assertSame(['answered' => false, 'reason' => FailureReason::SESSION_REVOKED->value], $second['result']);
                self::assertSame([], $second['events']);
                self::assertSame('revoked', DB::table('authentication_sessions')->sole()->revoked_reason);
            } else {
                self::assertSame(['answered' => true, 'reason' => null], $second['result']);
                self::assertSame($retry === 'refresh' ? [Refreshed::class] : [], $second['events']);
                self::assertNull(DB::table('authentication_sessions')->sole()->revoked_at);
            }

            $this->reset();
        }
    }

    /**
     * Rows of `[grace retry, change, failure]`.
     *
     * @return iterable<string, array{0: string, 1: string, 2: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     */
    public static function provideGraceRetriesAndChanges(): iterable
    {
        foreach (self::provideGraceRetries() as $name => [$retry]) {
            yield "{$name} of a revoked session" => [$retry, 'revoked', FailureReason::SESSION_REVOKED];
            yield "{$name} of a session returned to pending" => [$retry, 'pending', FailureReason::SESSION_PENDING];
            yield "{$name} of a session switched again" => [$retry, 'switched', FailureReason::ROTATION_REUSE];
        }
    }

    /**
     * A grace retry inside a REPEATABLE READ transaction is judged after its
     * guard.
     *
     * @param  string  $retry
     * @param  string  $change
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideGraceRetriesAndChanges')]
    public function testAGraceRetryInsideARepeatableReadTransactionIsJudgedAfterItsGuard(string $retry, string $change, FailureReason $reason): void
    {
        [, $first, $target] = $this->seedMemberships();

        $session  = $this->signIn($first);
        $again    = $this->graceRetryOf($retry, $session, $target);
        $rotation = $this->rotationOf($session);
        $changes  = match ($change) {
            'revoked' => ['revoked_at' => CarbonImmutable::now(), 'revoked_reason' => 'revoked'],
            'pending' => ['status' => 'pending'],
            default   => [
                'refresh_key'          => RefreshTokenHasher::hash(RefreshTokenHasher::successor(RefreshTokenHasher::successor($rotation))),
                'previous_refresh_key' => RefreshTokenHasher::hash(RefreshTokenHasher::successor($rotation)),
                'refresh_rotated_at'   => CarbonImmutable::now(),
            ],
        };

        $ran = false;

        DB::connection()->beforeExecuting(static function (string $query) use (&$ran, $changes): void {
            if ($ran || !str_contains($query, 'issuance_sequence')) {
                return;
            }

            $ran = true;

            DB::connection(self::COMPETITOR)->table('authentication_sessions')->update($changes);
        });

        self::beginTransactionAt('repeatable read');

        $outcome = null;
        $failure = self::serializationFailure(static function () use ($again, &$outcome): void {
            $outcome = $again();
        });

        self::assertTrue($ran);

        if (self::readsASnapshot('repeatable read')) {
            self::assertSame('40001', $failure);
            self::assertNull($outcome);

            return;
        }

        self::assertNull($failure);
        self::assertSame(['answered' => false, 'reason' => $reason->value], $outcome);
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

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('database.connections.' . self::COMPETITOR, $config->get('database.connections.testing'));
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
     * Sign the member in as the membership, then move the clocks on past its
     * first second.
     *
     * @param  \Tests\Integration\Fixtures\ActivatableTenantMembership  $membership
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(ActivatableTenantMembership $membership): SignedInSession
    {
        $context = SignInContext::fromRequest(request(), principal: $membership);
        $session = $this->sessions(self::GUARD)->signIn('password', self::credentials('member@example.test'), $context)->session;

        self::assertNotNull($session);

        $this->freezeAt(CarbonImmutable::now()->addSeconds(5));

        return $session;
    }

    /**
     * Use the session's first refresh token once and return a grace retry that
     * presents it again.
     *
     * @param  string  $retry
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @param  \Tests\Integration\Fixtures\ActivatableTenantMembership  $target
     * @return \Closure(): array{answered: bool, reason: ?string}
     *
     * @throws \Throwable
     */
    private function graceRetryOf(string $retry, SignedInSession $session, ActivatableTenantMembership $target): \Closure
    {
        $token  = $session->tokens->refreshToken?->reveal() ?? '';
        $answer = $retry === 'refresh'
            ? function () use ($token): array {
                $result = self::sessionsOf($this->freshGuard(self::GUARD))->refresh(PresentedRefreshToken::fromBody($token), self::requestClient());

                return ['answered' => $result->isRefreshed(), 'reason' => $result->reason?->value];
            }
        : function () use ($token, $target): array {
            $result = $this->sessions(self::GUARD)->switchTo(PresentedRefreshToken::fromBody($token), SwitchTarget::principal($target), self::requestClient());

            return ['answered' => $result->isSwitched(), 'reason' => $result->reason?->value];
        };

        self::assertSame(['answered' => true, 'reason' => null], $answer());

        $this->freezeAt(CarbonImmutable::now()->addSeconds(5));

        return $answer;
    }

    /**
     * The rotation id of the session's first refresh token.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return string
     */
    private function rotationOf(SignedInSession $session): string
    {
        $claims = $this->freshGuard(self::GUARD)->tokens()->parse($session->tokens->refreshToken?->reveal() ?? '', TokenType::REFRESH);

        self::assertIsArray($claims);
        self::assertIsString($claims[Claims::JWT_ID->value]);

        return $claims[Claims::JWT_ID->value];
    }

    /**
     * Run the first side in an open transaction, race the second in another
     * process, then commit or roll back.
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
     * Run the second side in the forked process, report its outcome and exit
     * without the parent's shutdown.
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
     * Clear the rows and the outcome a race left.
     *
     * @return void
     */
    private function reset(): void
    {
        foreach (['authentication_sessions', 'authentication_proofs', 'rate_limits', 'activatable_tenant_memberships', 'activatable_tenants'] as $table) {
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
     * Whether a step-up issued its access token, and why not.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\AccessTokenResult  $result
     * @return array{issued: bool, reason: ?string}
     */
    private static function stepUpOutcome(AccessTokenResult $result): array
    {
        return ['issued' => $result->isIssued(), 'reason' => $result->reason?->value];
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
