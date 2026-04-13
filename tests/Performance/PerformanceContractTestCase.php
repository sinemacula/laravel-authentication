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
 * Shared base for deterministic performance-contract tests.
 *
 * Records SQL emitted by a subject under test so the suite
 * can assert structural read/write budgets without making
 * flaky wall-clock assertions.
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
     */
    protected function freshJwtGuard(string $name): JwtGuard
    {
        PackageAuth::manager()->forgetGuards();

        $guard = PackageAuth::guard($name);

        assert($guard instanceof JwtGuard);

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

        $writes = array_values(
            array_filter(
                $this->capturedSql,
                static fn (string $sql): bool => preg_match('/^\s*(insert|update|delete|replace)\b/i', $sql) === 1,
            ),
        );

        $reads   = count($this->capturedSql) - count($writes);
        $queries = implode(' | ', $this->capturedSql);

        static::assertSame($expectedReads, $reads, "Unexpected read-query budget. Queries: {$queries}");
        static::assertSame($expectedWrites, count($writes), "Unexpected write-query budget. Queries: {$queries}");

        return $result;
    }
}
