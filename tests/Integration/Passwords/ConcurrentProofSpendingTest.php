<?php

declare(strict_types = 1);

namespace Tests\Integration\Passwords;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\IssuedCode;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Database\IdentityLock;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Passwords\ResetSubmissions;
use SineMacula\Laravel\Authentication\Sessions\DeviceRevocations;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use Tests\Concerns\ChangesIdentifiers;
use Tests\Integration\Fixtures\ChangeableIdentity;
use Tests\TestCase;

/**
 * Races, on PostgreSQL and MySQL, a password write against the flows that spend
 * a proof bound to the same identity (an identifier change confirmation, a
 * password reset), and a bulk revocation against a confirmation, each in a
 * process with a database connection of its own. The first is held open right
 * after the statement that would make the two lock their rows in opposite
 * orders; the second, started meanwhile, waits for it on the identity's row
 * (see `IdentityLock`) instead of deadlocking, so both answer a result and
 * neither throws.
 *
 * Skipped on SQLite, whose in-memory database each process would have to
 * itself, and where `pcntl` is not available.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentityLock::class)]
#[CoversClass(IdentifierChangeService::class)]
#[CoversClass(ResetSubmissions::class)]
#[CoversClass(DeviceRevocations::class)]
final class ConcurrentProofSpendingTest extends TestCase
{
    use ChangesIdentifiers;

    /** @var int How long the first operation is held after its statement once the second has started, in microseconds. */
    private const int HOLD_MICROSECONDS = 1000000;

    /** @var float The least time, in seconds, the second operation must have waited to show it waited on the first. */
    private const float LEAST_WAIT_SECONDS = 0.5;

    /** @var int How long the second operation waits to be started before giving up, in seconds. */
    private const int START_TIMEOUT_SECONDS = 10;

    /** @var string The new password the racing writes set. */
    private const string NEW_PASSWORD = 'a brand new long passphrase';

    /** @var string Directory the second operation reports its outcome in. */
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

        $this->outcomes = sys_get_temp_dir() . '/proof-race-' . bin2hex(random_bytes(8));

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
     * A password change racing a confirmation held after it deleted the pending
     * change waits for it: the change is made, then the password set.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordChangeWaitsForAConfirmation(): void
    {
        $identity = self::seedChangeable();
        $link     = $this->requestByLink($identity);

        [$first, $second] = $this->race(
            'delete from',
            'identifier_changes',
            fn (): string => $this->changes()->confirmByLink(Request::create($link))->value,
            static fn (): string => Auth::passwords('web')->set(self::reloaded($identity), self::NEW_PASSWORD, PasswordFlow::CHANGE)->isSet() ? 'set' : 'rejected',
        );

        self::assertSame(['changed', 'set'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(self::NEW_EMAIL, self::reloaded($identity)->email);
    }

    /**
     * A password change racing a confirmation held after it invalidated the old
     * address's live reset link waits for it as well.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordChangeWaitsForAConfirmationThatOutdatedAResetLink(): void
    {
        $identity = self::seedChangeable();
        $link     = $this->requestByLink($identity);

        self::resetToken();

        [$first, $second] = $this->race(
            'delete from',
            'one_time_codes',
            fn (): string => $this->changes()->confirmByLink(Request::create($link))->value,
            static fn (): string => Auth::passwords('web')->set(self::reloaded($identity), self::NEW_PASSWORD, PasswordFlow::CHANGE)->isSet() ? 'set' : 'rejected',
        );

        self::assertSame(['changed', 'set'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
    }

    /**
     * A reset with the old address's link racing a confirmation waits for it,
     * then finds the link outdated by the change: `invalid`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResetWaitsForAConfirmationAndFindsItsLinkOutdated(): void
    {
        $identity = self::seedChangeable();
        $link     = $this->requestByLink($identity);
        $token    = self::resetToken();

        [$first, $second] = $this->race(
            'delete from',
            'identifier_changes',
            fn (): string => $this->changes()->confirmByLink(Request::create($link))->value,
            static fn (): string => Auth::passwords('web')->reset(['email' => self::EMAIL, 'token' => $token, 'password' => self::NEW_PASSWORD])->status->value,
        );

        self::assertSame(['changed', 'invalid'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
    }

    /**
     * A password change racing a reset held after it spent its token waits for
     * it: the reset sets its password, then the change sets its own.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordChangeWaitsForAReset(): void
    {
        $identity = self::seedChangeable();
        $token    = self::resetToken();

        [$first, $second] = $this->race(
            'update',
            'one_time_codes',
            static fn (): string => Auth::passwords('web')->reset(['email' => self::EMAIL, 'token' => $token, 'password' => 'the reset passphrase'])->status->value,
            static fn (): string => Auth::passwords('web')->set(self::reloaded($identity), self::NEW_PASSWORD, PasswordFlow::CHANGE)->isSet() ? 'set' : 'rejected',
        );

        self::assertSame(['reset', 'set'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertTrue(Auth::guard('web')->getProvider()->validateCredentials(self::reloaded($identity), ['password' => self::NEW_PASSWORD]));
    }

    /**
     * A confirmation racing a revocation of every device held after it
     * cancelled the pending change waits for it, then finds the change gone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAConfirmationWaitsForABulkRevocationAndFindsTheChangeCancelled(): void
    {
        $identity = self::seedChangeable();
        $link     = $this->requestByLink($identity);

        self::seedDevice($identity);

        [$first, $second] = $this->race(
            'delete from',
            'identifier_changes',
            static fn (): string => (string) Auth::sessions('web')->revokeDevices(self::reloaded($identity), RevocationReason::REVOKED),
            fn (): string => $this->changes()->confirmByLink(Request::create($link))->value,
        );

        self::assertSame(['1', 'invalid'], [$first, $second['result']]);
        self::assertGreaterThanOrEqual(self::LEAST_WAIT_SECONDS, $second['waited']);
        self::assertSame(self::EMAIL, self::reloaded($identity)->email);
    }

    /**
     * Register the guards the tests change identifiers and passwords through.
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
     * Request a change of the identity's address, proven by link, and return
     * the link.
     *
     * @param  \Tests\Integration\Fixtures\ChangeableIdentity  $identity
     * @return string
     *
     * @throws \Throwable
     */
    private function requestByLink(ChangeableIdentity $identity): string
    {
        $link = $this->changes()->requestByLink($identity, 'email', self::NEW_EMAIL, Reauthentication::confirmedAt($this->now), 'email.confirm')->link();

        self::assertIsString($link);

        return $link;
    }

    /**
     * Issue a live reset link's token for the identity's current address
     * through the `web` guard, and return it.
     *
     * @return string
     *
     * @throws \Throwable
     */
    private static function resetToken(): string
    {
        $issued = app(OneTimeCodes::class)->issueToken(CodeBinding::passwordResetLink('web', 'email', self::EMAIL), CarbonImmutable::now()->startOfSecond(), 3600);

        self::assertInstanceOf(IssuedCode::class, $issued);

        return $issued->code;
    }

    /**
     * The identity as stored now.
     *
     * @param  \Tests\Integration\Fixtures\ChangeableIdentity  $identity
     * @return \Tests\Integration\Fixtures\ChangeableIdentity
     */
    private static function reloaded(ChangeableIdentity $identity): ChangeableIdentity
    {
        return ChangeableIdentity::query()->whereKey($identity->getKey())->firstOrFail();
    }

    /**
     * Run the first operation here, hold it open right after its first
     * statement of the verb on the table, start the second in another process
     * meanwhile, then let the first finish, and return both outcomes.
     *
     * @param  string  $verb
     * @param  string  $table
     * @param  \Closure(): string  $first
     * @param  \Closure(): string  $second
     * @return array{0: string, 1: array{result: string, waited: float}}
     *
     * @throws \Throwable
     */
    private function race(string $verb, string $table, \Closure $first, \Closure $second): array
    {
        DB::disconnect();

        $pid = pcntl_fork();

        if ($pid === 0) {
            $this->runInChild($second);
        }

        $held     = false;
        $outcomes = $this->outcomes;

        DB::listen(static function (QueryExecuted $query) use (&$held, $verb, $table, $outcomes): void {
            if ($held || !str_starts_with(strtolower($query->sql), $verb) || !str_contains($query->sql, $table)) {
                return;
            }

            $held = true;

            touch("{$outcomes}/start");
            usleep(self::HOLD_MICROSECONDS);
        });

        try {
            $result = $first();
        } finally {
            pcntl_waitpid($pid, $status);
        }

        $outcome = json_decode((string) file_get_contents("{$this->outcomes}/outcome"), true, flags: JSON_THROW_ON_ERROR);

        self::assertTrue($held);
        self::assertIsArray($outcome);
        self::assertArrayNotHasKey('error', $outcome);

        /** @var array{result: string, waited: float} $outcome */
        return [$result, $outcome];
    }

    /**
     * In the forked process: wait to be started, run the operation on a
     * connection of its own, report the outcome or the exception, and end
     * without running the parent's shutdown.
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
            $outcome = ['error' => $e::class . ': ' . $e->getMessage()];
        }

        file_put_contents("{$this->outcomes}/outcome", json_encode($outcome));

        posix_kill(posix_getpid(), SIGKILL);

        exit(1);
    }
}
