<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Sessions\DeferredBind;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Feature tests for binding the guard to a session a flow wrote once the writes
 * on its connection commit: at once with no transaction open, with no query; at
 * the commit inside one, after reading the session again, and only while the
 * guard serves the same request and the session is still the one written; never
 * on a rollback. What follows the bind runs whether or not it bound.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeferredBind::class)]
final class DeferredBindTest extends TestCase
{
    use InteractsWithSessions;

    /** @var list<string> What the bind and what follows it did, in order. */
    private array $done = [];

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

        $this->createSessionTables();
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
     * With no transaction open on the session's connection the bind runs at
     * once, without reading the session again, and then what follows it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithNoTransactionTheBindRunsAtOnceWithNoQuery(): void
    {
        $session    = $this->signedIn();
        $statements = $this->countStatements();

        $this->binds()->run($session->record, $session->principal, $this->step('bound'), $this->step('then'));

        self::assertSame(['bound', 'then'], $this->done);
        self::assertCount(0, $statements);
    }

    /**
     * Inside a transaction the bind waits for the commit, then reads the
     * session once and binds it, and what follows runs after it; with nothing
     * to follow, the bind alone runs. A rollback runs neither.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideATransactionTheBindWaitsForTheCommit(): void
    {
        $session = $this->signedIn();
        $binds   = $this->binds();

        DB::beginTransaction();

        $binds->run($session->record, $session->principal, $this->step('bound'), $this->step('then'));

        self::assertSame([], $this->done);

        $statements = $this->countStatements();

        DB::commit();

        self::assertSame(['bound', 'then'], $this->done);
        self::assertCount(1, $statements);

        $this->done = [];

        DB::transaction(fn () => $binds->run($session->record, $session->principal, $this->step('bound')));

        self::assertSame(['bound'], $this->done);

        $this->done = [];

        DB::beginTransaction();

        $binds->run($session->record, $session->principal, $this->step('bound'), $this->step('then'));

        DB::rollBack();

        self::assertSame([], $this->done);
    }

    /**
     * A bind that waited is not made once the guard serves another request,
     * though what follows it still runs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABindThatWaitedIsNotMadeForAnotherRequest(): void
    {
        $session = $this->signedIn();
        $guard   = $this->freshGuard();
        $binds   = new DeferredBind($guard->context(), self::afterCommit());

        DB::transaction(function () use ($binds, $session, $guard): void {
            $binds->run($session->record, $session->principal, $this->step('bound'), $this->step('then'));

            $guard->context()->rebindRequest(Request::create('/another'));
        });

        self::assertSame(['then'], $this->done);
    }

    /**
     * Rows of `[what the transaction wrote to the session before its commit]`.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideChangesBeforeTheCommit(): iterable
    {
        yield 'revoked' => [['revoked_at' => '2026-04-06 12:00:00', 'revoked_reason' => 'signed_out']];
        yield 'returned to pending' => [['status' => 'pending']];
        yield 'past its idle deadline' => [['idle_expires_at' => '2026-04-06 12:00:00']];
        yield 'another session put under its key' => [['generation' => '00000000-0000-7000-8000-000000000000']];
        yield 'switched to another principal' => [['principal_id' => '999999']];
        yield 'switched to another tenant' => [['tenant_id' => 'another-tenant']];
        yield 'moved to another guard' => [['guard' => 'admin']];
    }

    /**
     * A bind that waited is not made for a session the transaction changed so
     * it is no longer the one written: revoked, returned to pending, ended,
     * replaced, switched, or of another guard; what follows it still runs.
     *
     * @param  array<string, mixed>  $change
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChangesBeforeTheCommit')]
    public function testABindThatWaitedIsNotMadeForASessionChangedBeforeTheCommit(array $change): void
    {
        $session = $this->signedIn();
        $binds   = $this->binds();

        DB::transaction(function () use ($binds, $session, $change): void {
            $binds->run($session->record, $session->principal, $this->step('bound'), $this->step('then'));

            DB::table('authentication_sessions')->update($change);
        });

        self::assertSame(['then'], $this->done);
    }

    /**
     * Register the session guards.
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
     * A session the identity signed in to on the `api` guard.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(): SignedInSession
    {
        $this->seedIdentity();

        $session = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Binds on a fresh `api` guard's context.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\DeferredBind
     */
    private function binds(): DeferredBind
    {
        return new DeferredBind($this->freshGuard()->context(), self::afterCommit());
    }

    /**
     * Deferral to the commit of the transactions manager bound when it is
     * asked, as the session service builds it.
     *
     * @return \SineMacula\Laravel\Authentication\Database\AfterCommit
     */
    private static function afterCommit(): AfterCommit
    {
        return new AfterCommit(static fn (): mixed => app()->bound('db.transactions') ? app('db.transactions') : null);
    }

    /**
     * A step that records its name when it runs.
     *
     * @param  string  $name
     * @return \Closure(): void
     */
    private function step(string $name): \Closure
    {
        return function () use ($name): void {
            $this->done[] = $name;
        };
    }

    /**
     * Count the statements run from here on.
     *
     * @return \ArrayObject<int, string>
     */
    private function countStatements(): \ArrayObject
    {
        /** @var \ArrayObject<int, string> $statements */
        $statements = new \ArrayObject;

        DB::listen(static function (QueryExecuted $query) use ($statements): void {
            $statements->append($query->sql);
        });

        return $statements;
    }
}
