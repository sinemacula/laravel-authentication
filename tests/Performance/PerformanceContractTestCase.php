<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use Tests\TestCase;

/**
 * Base for performance contracts that assert the SQL a subject runs instead of
 * its wall-clock time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
abstract class PerformanceContractTestCase extends TestCase
{
    /** @var \Carbon\Carbon Frozen clock used by JWT and timestamp-sensitive paths. */
    protected Carbon $now;

    /** @var list<string> SQL statements captured during the measured section. */
    private array $capturedSql = [];

    /**
     * Freeze the clock and attach a query listener.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = Carbon::createStrict(2026, 4, 10, 12, 0, 0);

        Carbon::setTestNow($this->now);
        JWT::$timestamp = $this->now->getTimestamp();

        DB::listen(function (QueryExecuted $query): void {
            $this->capturedSql[] = $query->sql;
        });
    }

    /**
     * Release the frozen clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();
        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * Bind the current request to a bearer token.
     *
     * @param  string  $path
     * @param  string  $token
     * @return void
     */
    protected function bindRequestWithBearer(string $path, #[\SensitiveParameter] string $token): void
    {
        app()->instance('request', Request::create($path, 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $token,
        ]));
    }

    /**
     * Resolve a fresh JWT guard for the supplied name.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function freshJwtGuard(string $name): JwtGuard
    {
        PackageAuth::manager()->forgetGuards();

        $guard = PackageAuth::guard($name);

        static::assertInstanceOf(JwtGuard::class, $guard); // @phpstan-ignore staticMethod.impossibleType

        return $guard;
    }

    /**
     * Run a subject and assert the exact SQL read/write budget.
     *
     * @template TResult
     *
     * @param  int  $expectedReads
     * @param  int  $expectedWrites
     * @param  callable(): TResult  $callback
     * @return TResult
     */
    protected function assertQueryBudget(int $expectedReads, int $expectedWrites, callable $callback): mixed
    {
        $this->capturedSql = [];

        $result = $callback();

        $writes = array_filter(
            $this->capturedSql,
            static fn (string $sql): bool => preg_match('/^\s*(insert|update|delete|replace)\b/i', $sql) === 1,
        );

        $reads   = count($this->capturedSql) - count($writes);
        $queries = implode(' | ', $this->capturedSql);

        static::assertSame($expectedReads, $reads, "Unexpected read-query budget. Queries: {$queries}");
        static::assertCount($expectedWrites, $writes, "Unexpected write-query budget. Queries: {$queries}");

        return $result;
    }

    /**
     * How many reads of a session's first factor the last budget captured: the
     * one proof of its first kind, oldest first.
     *
     * @return int
     */
    protected function firstFactorReads(): int
    {
        return count(preg_grep('/authentication_proofs.+order by .?authenticated_at.? asc, .?sequence.? asc limit 1/i', $this->capturedSql) ?: []);
    }
}
