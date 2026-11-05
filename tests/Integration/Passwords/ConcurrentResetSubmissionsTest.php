<?php

declare(strict_types = 1);

namespace Tests\Integration\Passwords;

use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\DeadlockException;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Events\PasswordSet;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Passwords\Enums\ResetStatus;
use SineMacula\Laravel\Authentication\Passwords\ResetResult;
use SineMacula\Laravel\Authentication\Passwords\ResetSubmissions;
use Tests\Concerns\InteractsWithPasswordResets;
use Tests\Integration\Fixtures\PasswordIdentity;
use Tests\TestCase;

/**
 * Integration tests of password resets against the engine the suite runs on,
 * where another request changes the token between a reset's read and its
 * writes, and where the reset fails or its caller rolls back: the token is
 * spent together with the new password, the cutoff and the revocation, or not
 * at all. On PostgreSQL and MySQL, a reset deadlocked inside a caller's
 * transaction by another process fails as a deadlock the caller can retry whole
 * (skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResetSubmissions::class)]
final class ConcurrentResetSubmissionsTest extends TestCase
{
    use InteractsWithPasswordResets;

    /** @var int How long the forked side waits, once the reset waits on the code row, before it asks for the identity's row, in microseconds: under PostgreSQL's one-second deadlock check, so the reset, which has waited longer, is the side that finds the cycle. */
    private const int CROSS_MICROSECONDS = 300000;

    /** @var int How long either side waits for the other before giving up, in seconds. */
    private const int START_TIMEOUT_SECONDS = 10;

    /**
     * Of two resets with one token, the one that spends it first resets the
     * password; the other, which read the token live, is `invalid`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoResetsWithOneTokenResetOnce(): void
    {
        self::seedResettable();

        $token = $this->requestLink();
        $other = null;

        $this->afterTheTokenIsRead(function () use ($token, &$other): void {
            $other = $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => 'the other passphrase']);
        });

        $first = $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD]);

        self::assertInstanceOf(ResetResult::class, $other);
        self::assertSame([ResetStatus::INVALID, ResetStatus::RESET], [$first->status, $other->status]);
        self::assertTrue(app(Hasher::class)->check('the other passphrase', (string) PasswordIdentity::query()->sole()->password));
    }

    /**
     * A new link issued between a reset's read of the token and its spending it
     * makes the reset `invalid`, and the new link resets.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetRacingANewLinkIsInvalid(): void
    {
        config()->set('authentication.codes.resend_cooldown_seconds', 0);

        self::seedResettable();

        $token = $this->requestLink();
        $fresh = null;

        $this->afterTheTokenIsRead(static function () use (&$fresh): void {
            $fresh = app(OneTimeCodes::class)->issueToken(CodeBinding::passwordResetLink('web', 'email', self::EMAIL), now()->toImmutable(), 3600);
        });

        self::assertSame(ResetStatus::INVALID, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->status);
        self::assertInstanceOf(IssuedCode::class, $fresh);
        self::assertSame(ResetStatus::RESET, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $fresh->code(), 'password' => self::NEW_PASSWORD])->status);
    }

    /**
     * A failure after the password is written (the sessions cannot be revoked)
     * rolls the token, the password, the cutoff and the sessions back together,
     * reports nothing, and propagates.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailureAfterThePasswordRollsEverythingBack(): void
    {
        self::seedResettable();

        $this->signInWithPassword('web', self::EMAIL);

        $token = $this->requestLink();

        $this->recordEvents([PasswordSet::class, SessionRevoked::class, SignedOutEverywhere::class]);

        DB::connection()->beforeExecuting(static function (string $query): void {
            if (str_starts_with($query, 'update') && str_contains($query, 'authentication_sessions')) {
                throw new \RuntimeException('The revocation failed.');
            }
        });

        try {
            $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD]);
            self::fail('The failing revocation was swallowed.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The revocation failed.', $exception->getMessage());
        }

        $identity = PasswordIdentity::query()->sole();

        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) $identity->password));
        self::assertNull($identity->tokens_valid_after);
        self::assertNull(DB::table('authentication_sessions')->value('revoked_at'));
        self::assertNull(DB::table('one_time_codes')->value('consumed_at'));
        self::assertSame([], $this->recordedClasses());
    }

    /**
     * A reset inside a transaction its caller rolls back resets nothing and
     * reports nothing, and the token can still reset.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACallersRollbackUndoesTheReset(): void
    {
        self::seedResettable();

        $this->signInWithPassword('web', self::EMAIL);

        $token = $this->requestLink();

        $this->recordEvents([PasswordSet::class, SessionRevoked::class, SignedOutEverywhere::class]);

        DB::beginTransaction();

        self::assertSame(ResetStatus::RESET, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->status);

        DB::rollBack();

        self::assertSame([], $this->recordedClasses());
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) PasswordIdentity::query()->sole()->password));
        self::assertNull(DB::table('authentication_sessions')->value('revoked_at'));
        self::assertSame(ResetStatus::RESET, $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->status);
    }

    /**
     * A reset inside a caller's transaction that deadlocks with another process
     * (which wrote the reset's code row, then asks for the identity's row the
     * reset holds) is thrown on as Laravel's `DeadlockException` with the
     * caller's transaction level restored: the package rolls nothing back to
     * the reset's savepoint itself (Laravel 13.40 and later tries to), which on
     * MySQL the deadlock has already dropped with the whole transaction. The
     * caller rolls back, nothing the reset did is kept, and its retry of the
     * whole transaction resets.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetDeadlockedInsideACallersTransactionIsThrownOnAsADeadlock(): void
    {
        if (DB::connection()->getDriverName() === 'sqlite' || !function_exists('pcntl_fork')) {
            self::markTestSkipped('Racing processes need a shared database server and pcntl.');
        }

        $identity = self::seedResettable();

        $this->signInWithPassword('web', self::EMAIL);

        $token    = $this->requestLink();
        $outcomes = sys_get_temp_dir() . '/reset-deadlock-' . bin2hex(random_bytes(8));

        mkdir($outcomes);

        try {
            DB::disconnect();

            $pid = pcntl_fork();

            if ($pid < 0) {
                self::fail('The second side could not be forked.');
            }

            if ($pid === 0) {
                self::crossInChild($outcomes, $identity->getKey());
            }

            self::awaitHeld($outcomes, $pid);

            DB::beginTransaction();

            try {
                $thrown = $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD]);
            } catch (\Throwable $exception) {
                $thrown = $exception;
            }

            $level = DB::transactionLevel();

            DB::rollBack();

            pcntl_waitpid($pid, $status);

            self::assertSame(['crossed' => true], json_decode((string) file_get_contents("{$outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR));
        } finally {
            array_map(unlink(...), glob("{$outcomes}/*") ?: []);
            rmdir($outcomes);
        }

        self::assertInstanceOf(DeadlockException::class, $thrown);
        self::assertSame(1, $level);
        self::assertSame(0, DB::transactionLevel());
        self::assertTrue(app(Hasher::class)->check(self::PASSWORD, (string) PasswordIdentity::query()->sole()->password));
        self::assertNull(PasswordIdentity::query()->sole()->tokens_valid_after);
        self::assertNull(DB::table('authentication_sessions')->value('revoked_at'));
        self::assertNull(DB::table('one_time_codes')->value('consumed_at'));

        $retried = DB::transaction(fn (): ResetResult => $this->passwords()->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD]));

        self::assertSame([ResetStatus::RESET, 1], [$retried->status, $retried->revoked]);
        self::assertTrue(app(Hasher::class)->check(self::NEW_PASSWORD, (string) PasswordIdentity::query()->sole()->password));
    }

    /**
     * Run the change once, right after the next reset reads the token and
     * before it spends it, as a concurrent request would.
     *
     * @param  \Closure(): void  $change
     * @return void
     */
    private function afterTheTokenIsRead(\Closure $change): void
    {
        $done = false;

        DB::listen(static function (QueryExecuted $query) use ($change, &$done): void {
            $sql = strtolower($query->sql);

            if ($done || !str_starts_with($sql, 'select') || !str_contains($sql, 'one_time_codes')) {
                return;
            }

            $done = true;

            $change();
        });
    }

    /**
     * Wait until the forked side holds the code row, killing it and failing
     * when it never does.
     *
     * @param  string  $outcomes
     * @param  int  $pid
     * @return void
     */
    private static function awaitHeld(string $outcomes, int $pid): void
    {
        $deadline = microtime(true) + self::START_TIMEOUT_SECONDS;

        while (!is_file("{$outcomes}/held") && microtime(true) < $deadline) {
            usleep(5000);
        }

        if (is_file("{$outcomes}/held")) {
            return;
        }

        posix_kill($pid, SIGKILL);
        pcntl_waitpid($pid, $status);

        self::fail('The forked side never held the code row.');
    }

    /**
     * In the forked process: on a connection of its own, write the reset's code
     * row in a transaction, several times so its transaction is the heavier and
     * MySQL picks the other as the deadlock's victim, signal that it holds it,
     * wait until the parent's reset, having locked the identity's row, waits on
     * the code row, then ask for the identity's row, closing the cycle; once
     * the database has failed the parent, roll back, report, and end without
     * running the parent's shutdown. A reset that never waits is reported as an
     * error.
     *
     * @param  string  $outcomes
     * @param  mixed  $identity
     * @return never
     */
    private static function crossInChild(string $outcomes, mixed $identity): never
    {
        try {
            DB::beginTransaction();

            foreach (range(1, 5) as $ignored) {
                DB::table('one_time_codes')->where('id', self::bindingDigest(CodeBinding::passwordResetLink('web', 'email', self::EMAIL)))->increment('attempts');
            }

            touch("{$outcomes}/held");

            self::awaitAWaiter();

            usleep(self::CROSS_MICROSECONDS);

            DB::table('password_identities')->where('id', $identity)->lockForUpdate()->first();
            DB::rollBack();

            $outcome = ['crossed' => true];
        } catch (\Throwable $e) {
            $outcome = ['error' => $e->getMessage()];
        }

        file_put_contents("{$outcomes}/outcome", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }

    /**
     * Wait until another connection waits on a lock this connection's
     * transaction holds, for as long as either side waits for the other.
     *
     * @return void
     *
     * @throws \RuntimeException
     */
    private static function awaitAWaiter(): void
    {
        $deadline = microtime(true) + self::START_TIMEOUT_SECONDS;

        while (!self::isWaitedOn()) {
            if (microtime(true) >= $deadline) {
                throw new \RuntimeException('Nothing waited on the locks this side holds.');
            }

            usleep(5000);
        }
    }

    /**
     * Whether another connection waits on a lock this connection's transaction
     * holds, as the engine's lock-wait view reports it. PostgreSQL's is read
     * from `pg_locks`, because `pg_stat_activity` keeps the backends of its
     * first read in a transaction, before the waiter has connected.
     *
     * @return bool
     */
    private static function isWaitedOn(): bool
    {
        return DB::connection()->getDriverName() === 'pgsql'
            ? DB::table('pg_locks')
                ->where('granted', false)
                ->whereRaw('pg_backend_pid() = any(pg_blocking_pids(pid))')
                ->exists()
            : DB::table('performance_schema.data_lock_waits as waits')
                ->join('performance_schema.threads as threads', 'threads.THREAD_ID', '=', 'waits.BLOCKING_THREAD_ID')
                ->whereRaw('threads.PROCESSLIST_ID = connection_id()')
                ->exists();
    }
}
