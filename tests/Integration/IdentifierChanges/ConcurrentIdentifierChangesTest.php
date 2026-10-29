<?php

declare(strict_types = 1);

namespace Tests\Integration\IdentifierChanges;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\IdentifierChanges\ChangeConfirmation;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeOutcome;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use Tests\Concerns\ChangesIdentifiers;
use Tests\Integration\Fixtures\ChangeableIdentity;
use Tests\TestCase;

/**
 * Races identifier change confirmations on PostgreSQL and MySQL, each in a
 * process with a database connection of its own: one runs inside a transaction
 * it holds open, and the other, started meanwhile, waits on a row the first
 * wrote. Two confirmations of one change make it once; two identities
 * confirming changes to one identifier get it once, the other refused by the
 * unique index as taken with its change left pending; and when the first rolls
 * back, the one that waited makes its change.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierChangeService::class)]
#[CoversClass(ChangeConfirmation::class)]
final class ConcurrentIdentifierChangesTest extends TestCase
{
    use ChangesIdentifiers;

    /** @var int How long the first confirmation holds its transaction open once the second has started, in microseconds. */
    private const int HOLD_MICROSECONDS = 1000000;

    /** @var float The least time, in seconds, the second confirmation must have waited to show it waited on the first. */
    private const float LEAST_WAIT_SECONDS = 0.5;

    /** @var int How long the second confirmation waits to be started before giving up, in seconds. */
    private const int START_TIMEOUT_SECONDS = 10;

    /** @var string Directory the second confirmation reports its outcome in. */
    private string $outcomes;

    /**
     * Skip where processes cannot share the database, and start from a known
     * moment with the fakes bound and the route links point at.
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

        $this->startChanging();

        Route::get('/email/confirm', static fn (): string => 'ok')->name('email.confirm');

        $this->outcomes = sys_get_temp_dir() . '/change-race-' . bin2hex(random_bytes(8));

        mkdir($this->outcomes);
    }

    /**
     * Remove the outcomes, drop the table and release the clock.
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

            $this->stopChanging();
        }

        parent::tearDown();
    }

    /**
     * Of two confirmations of one change, the one whose transaction commits
     * first makes it; the one that waited on the pending change finds it gone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoConfirmationsOfOneChangeMakeItOnce(): void
    {
        $link = $this->requestByLink(self::seedChangeable(), self::NEW_EMAIL);

        [$first, $second] = $this->race(
            fn (): string => $this->changes()->confirmByLink(Request::create($link))->value,
            fn (): string => $this->changes()->confirmByLink(Request::create($link))->value,
            commitFirst: true,
        );

        self::assertSame(IdentifierChangeOutcome::CHANGED->value, $first);
        self::assertSame(IdentifierChangeOutcome::INVALID->value, $second['result']);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame([self::NEW_EMAIL], DB::table('changeable_identities')->pluck('email')->all());
    }

    /**
     * Two identities confirming changes to one identifier: the provider's look
     * finds neither holding it, so the unique index decides; the one that
     * waited on it is taken, and its change stays pending, proof unspent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTwoIdentitiesRacingForOneIdentifierGetItOnce(): void
    {
        $first  = $this->requestByLink(self::seedChangeable(), self::NEW_EMAIL);
        $second = $this->requestByLink(self::seedChangeable('bea@example.test'), self::NEW_EMAIL);

        [$won, $lost] = $this->race(
            fn (): string => $this->changes()->confirmByLink(Request::create($first))->value,
            fn (): string => $this->changes()->confirmByLink(Request::create($second))->value,
            commitFirst: true,
        );

        self::assertSame(IdentifierChangeOutcome::CHANGED->value, $won);
        self::assertSame(IdentifierChangeOutcome::TAKEN->value, $lost['result']);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $lost['waited']);
        self::assertSame([self::NEW_EMAIL, 'bea@example.test'], DB::table('changeable_identities')->orderBy('id')->pluck('email')->all());
        self::assertSame(['bea@example.test'], DB::table('identifier_changes')->pluck('previous')->all());
    }

    /**
     * When the first confirmation rolls back, the one that waited on the unique
     * index makes its change instead.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConfirmationWaitingOnOneThatRollsBackMakesItsChange(): void
    {
        $first  = $this->requestByLink(self::seedChangeable(), self::NEW_EMAIL);
        $second = $this->requestByLink(self::seedChangeable('bea@example.test'), self::NEW_EMAIL);

        [, $outcome] = $this->race(
            fn (): string => $this->changes()->confirmByLink(Request::create($first))->value,
            fn (): string => $this->changes()->confirmByLink(Request::create($second))->value,
            commitFirst: false,
        );

        self::assertSame(IdentifierChangeOutcome::CHANGED->value, $outcome['result']);
        self::assertSame([self::EMAIL, self::NEW_EMAIL], DB::table('changeable_identities')->orderBy('id')->pluck('email')->all());
    }

    /**
     * Register the guards the tests change identifiers through.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureChangeGuards($app->make(ConfigRepository::class));
    }

    /**
     * Request a change of the identity's address to the one given, proven by
     * link, and return the link.
     *
     * @param  \Tests\Integration\Fixtures\ChangeableIdentity  $identity
     * @param  string  $email
     * @return string
     *
     * @throws \Throwable
     */
    private function requestByLink(ChangeableIdentity $identity, string $email): string
    {
        $link = $this->changes()->requestByLink($identity, 'email', $email, Reauthentication::confirmedAt($this->now), 'email.confirm')->link();

        self::assertIsString($link);

        return $link;
    }

    /**
     * Run the first confirmation here inside a transaction, start the second in
     * another process, hold the transaction open while the second waits, then
     * commit or roll back, and return both outcomes.
     *
     * @param  \Closure(): string  $first
     * @param  \Closure(): string  $second
     * @param  bool  $commitFirst
     * @return array{0: string, 1: array{result: string, waited: float}}
     *
     * @throws \Throwable
     */
    private function race(\Closure $first, \Closure $second, bool $commitFirst): array
    {
        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid === 0) {
            $this->runInChild($second);
        }

        DB::beginTransaction();

        $result = $first();

        touch("{$this->outcomes}/start");
        usleep(self::HOLD_MICROSECONDS);

        $commitFirst ? DB::commit() : DB::rollBack();

        pcntl_waitpid($pid, $status);

        $outcome = json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        self::assertIsArray($outcome);
        self::assertArrayNotHasKey('error', $outcome);

        /** @var array{result: string, waited: float} $outcome */
        return [$result, $outcome];
    }

    /**
     * In the forked process: wait to be started, run the confirmation on a
     * connection of its own, report the outcome, and end without running the
     * parent's shutdown.
     *
     * @param  \Closure(): string  $operation
     * @return never
     */
    private function runInChild(\Closure $operation): never
    {
        try {
            $deadline = microtime(true) + self::START_TIMEOUT_SECONDS;

            while (!is_file("{$this->outcomes}/start") && microtime(true) < $deadline) {
                usleep(5000);
            }

            $started = microtime(true);
            $outcome = ['result' => $operation(), 'waited' => microtime(true) - $started];
        } catch (\Throwable $e) {
            $outcome = ['error' => $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/outcome", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }
}
