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
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\SessionEstablishment;
use SineMacula\Laravel\Authentication\Sessions\SessionWriter;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Proofs\UndescribedFirstFactor;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Races a sign-in that replaces the client's previous session against other
 * writers of that session, each in its own process.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionWriter::class)]
#[CoversClass(SessionEstablishment::class)]
final class ConcurrentSignInReplacementTest extends TestCase
{
    use InteractsWithSessions;

    /** @var int How long the first side holds its transaction open once the second has started, in microseconds. */
    private const int HOLD_MICROSECONDS = 1000000;

    /** @var float The least time, in seconds, the second side must have waited to show it waited on the first. */
    private const float LEAST_WAIT_SECONDS = 0.5;

    /** @var int How long the second side waits to be started before giving up, in seconds. */
    private const int START_TIMEOUT_SECONDS = 10;

    /** @var list<class-string> The events both sides record. */
    private const array EVENTS = [SessionRevoked::class, SessionCreated::class, SignedIn::class, Refreshed::class, SignedOutEverywhere::class];

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

        $this->outcomes = sys_get_temp_dir() . '/replacement-race-' . bin2hex(random_bytes(8));

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
     * Two sign-ins with the same proof revoke the previous session once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoSignInsWithTheSameProofRevokeThePreviousSessionOnce(): void
    {
        foreach ([true, false] as $commit) {

            $identity = $this->seedIdentity();
            $previous = $this->signIn($identity);

            [$first, $second] = $this->race(
                fn (): string => $this->replacing($identity, $previous),
                fn (): string => $this->replacing($identity, $previous),
                $commit,
            );

            self::assertSame('superseded', $this->reasonOf($previous));

            if ($commit) {
                self::assertSame([SessionRevoked::class, SessionCreated::class, SignedIn::class], $this->recordedClasses());
                self::assertSame([SessionCreated::class, SignedIn::class], $second['events']);
                self::assertSame(3, DB::table('authentication_sessions')->count());
                self::assertSame(2, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
                self::assertNull($this->reasonOf($first));
            } else {
                self::assertSame([], $this->recordedClasses());
                self::assertSame([SessionRevoked::class, SessionCreated::class, SignedIn::class], $second['events']);
                self::assertSame(2, DB::table('authentication_sessions')->count());
            }

            self::assertIsString($second['result']);
            self::assertNull($this->reasonOf($second['result']));

            $this->reset();
        }
    }

    /**
     * A sign-in waiting on a refresh of its proof follows its outcome.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInWaitingOnARefreshOfItsProofFollowsItsOutcome(): void
    {
        foreach ([true, false] as $commit) {

            $identity = $this->seedIdentity();
            $previous = $this->signIn($identity);

            [$refreshed, $second] = $this->race(
                fn (): bool => self::sessionsOf($this->freshGuard())->refresh(
                    self::bodyToken($previous->tokens),
                    self::requestClient(),
                )->isRefreshed(),
                fn (): string => $this->replacing($identity, $previous),
                $commit,
            );

            self::assertTrue($refreshed);
            self::assertNotSame(IdentifierCoercion::stringify($previous->record->getKey()), $second['result']);

            if ($commit) {
                self::assertSame([Refreshed::class, SignedIn::class], $this->recordedClasses());
                self::assertSame([SessionCreated::class, SignedIn::class], $second['events']);
                self::assertNull($this->revokedAtOf($previous));
            } else {
                self::assertSame([], $this->recordedClasses());
                self::assertSame([SessionRevoked::class, SessionCreated::class, SignedIn::class], $second['events']);
                self::assertSame('superseded', $this->reasonOf($previous));
            }

            $this->reset();
        }
    }

    /**
     * A refresh waiting on a replacement follows its outcome.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefreshWaitingOnAReplacementFollowsItsOutcome(): void
    {
        foreach ([true, false] as $commit) {

            $identity = $this->seedIdentity();
            $previous = $this->signIn($identity);

            [$replacement, $second] = $this->race(
                fn (): string => $this->replacing($identity, $previous),
                fn (): ?string => self::sessionsOf($this->freshGuard())->refresh(
                    self::bodyToken($previous->tokens),
                    self::requestClient(),
                )->reason?->value,
                $commit,
            );

            if ($commit) {
                self::assertSame(FailureReason::SESSION_REVOKED->value, $second['result']);
                self::assertSame([], $second['events']);
                self::assertSame('superseded', $this->reasonOf($previous));
                self::assertNull($this->revokedAtOf($replacement));
            } else {
                self::assertNull($second['result']);
                self::assertSame([Refreshed::class, SignedIn::class], $second['events']);
                self::assertNull($this->revokedAtOf($previous));
            }

            $this->reset();
        }
    }

    /**
     * A revocation of the session and a replacement revoke it once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARevocationOfTheSessionAndAReplacementRevokeItOnce(): void
    {
        $identity = $this->seedIdentity();
        $previous = $this->signIn($identity);

        [$revoked, $second] = $this->race(
            fn (): bool => $this->sessions()->revokeSession($identity, $previous->record->getKey(), RevocationReason::REVOKED),
            fn (): string => $this->replacing($identity, $previous),
            true,
        );

        self::assertTrue($revoked);
        self::assertSame('revoked', $this->reasonOf($previous));
        self::assertSame([SessionRevoked::class], $this->recordedClasses());
        self::assertSame([SessionCreated::class, SignedIn::class], $second['events']);
        self::assertIsString($second['result']);
        self::assertNull($this->revokedAtOf($second['result']));

        $this->reset();

        $identity = $this->seedIdentity();
        $previous = $this->signIn($identity);

        [$replacement, $second] = $this->race(
            fn (): string => $this->replacing($identity, $previous),
            fn (): bool => $this->sessions()->revokeSession($identity, $previous->record->getKey(), RevocationReason::REVOKED),
            true,
        );

        self::assertFalse($second['result']);
        self::assertSame([], $second['events']);
        self::assertSame('superseded', $this->reasonOf($previous));
        self::assertSame([SessionRevoked::class, SessionCreated::class, SignedIn::class], $this->recordedClasses());
        self::assertNull($this->revokedAtOf($replacement));
    }

    /**
     * A replacement waiting on a sign-out everywhere follows its outcome.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReplacementWaitingOnASignOutEverywhereFollowsItsOutcome(): void
    {
        foreach ([true, false] as $commit) {

            $identity = $this->seedIdentity();
            $previous = $this->signIn($identity);

            [$count, $second] = $this->race(
                fn (): int => $this->sessions()->revokeSessions($identity, RevocationReason::SIGNED_OUT_EVERYWHERE),
                fn (): string => $this->replacing($identity, $previous),
                $commit,
            );

            self::assertSame(1, $count);
            self::assertIsString($second['result']);
            self::assertNull($this->revokedAtOf($second['result']));

            if ($commit) {
                self::assertSame([SessionRevoked::class, SignedOutEverywhere::class], $this->recordedClasses());
                self::assertSame([SessionCreated::class, SignedIn::class], $second['events']);
                self::assertSame('signed_out_everywhere', $this->reasonOf($previous));
            } else {
                self::assertSame([], $this->recordedClasses());
                self::assertSame([SessionRevoked::class, SessionCreated::class, SignedIn::class], $second['events']);
                self::assertSame('superseded', $this->reasonOf($previous));
            }

            $this->reset();
        }
    }

    /**
     * A sign-out everywhere waiting on a replacement follows its outcome.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignOutEverywhereWaitingOnAReplacementFollowsItsOutcome(): void
    {
        foreach ([true, false] as $commit) {

            $identity = $this->seedIdentity();
            $previous = $this->signIn($identity);

            [$replacement, $second] = $this->race(
                fn (): string => $this->replacing($identity, $previous),
                fn (): int => $this->sessions()->revokeSessions($identity, RevocationReason::SIGNED_OUT_EVERYWHERE),
                $commit,
            );

            if ($commit) {
                self::assertSame(0, $second['result']);
                self::assertSame([SignedOutEverywhere::class], $second['events']);
                self::assertSame([SessionRevoked::class, SessionCreated::class, SignedIn::class], $this->recordedClasses());
                self::assertSame('superseded', $this->reasonOf($previous));
                self::assertNull($this->revokedAtOf($replacement));
            } else {
                self::assertSame(1, $second['result']);
                self::assertSame([SessionRevoked::class, SignedOutEverywhere::class], $second['events']);
                self::assertSame('signed_out_everywhere', $this->reasonOf($previous));
                self::assertSame(1, DB::table('authentication_sessions')->count());
            }

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
     * Start a session for the identity, then move the clocks on past its first
     * second.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(IntegrationIdentity $identity): SignedInSession
    {
        $session = $this->sessions()->start(UndescribedFirstFactor::of($identity), null, 'sso', self::requestContext())->session;

        self::assertNotNull($session);

        $this->freezeAt(CarbonImmutable::now()->addSeconds(5));

        return $session;
    }

    /**
     * Start a session for the identity that proves the previous one, and return
     * its key.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $previous
     * @return string
     *
     * @throws \Throwable
     */
    private function replacing(IntegrationIdentity $identity, SignedInSession $previous): string
    {
        $context = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), refreshToken: $previous->tokens->refreshToken?->reveal());
        $session = $this->sessions()->start(UndescribedFirstFactor::of($identity), null, 'sso', $context)->session;

        self::assertNotNull($session);

        return (string) IdentifierCoercion::stringify($session->record->getKey());
    }

    /**
     * The revocation reason the session's row records.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession|string  $record
     * @return ?string
     */
    private function reasonOf(SignedInSession|string $record): ?string
    {
        $value = DB::table('authentication_sessions')->where('id', self::keyOf($record))->value('revoked_reason');

        return is_string($value) ? $value : null;
    }

    /**
     * The revocation time the session's row records, as stored.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession|string  $record
     * @return mixed
     */
    private function revokedAtOf(SignedInSession|string $record): mixed
    {
        self::assertTrue(DB::table('authentication_sessions')->where('id', self::keyOf($record))->exists());

        return DB::table('authentication_sessions')->where('id', self::keyOf($record))->value('revoked_at');
    }

    /**
     * The key of the session, or the key itself.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession|string  $record
     * @return string
     */
    private static function keyOf(SignedInSession|string $record): string
    {
        return is_string($record) ? $record : (string) IdentifierCoercion::stringify($record->record->getKey());
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
        foreach (['authentication_sessions', 'rate_limits', 'integration_identities'] as $table) {
            DB::table($table)->delete();
        }

        unlink("{$this->outcomes}/start");
        unlink("{$this->outcomes}/outcome");
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
