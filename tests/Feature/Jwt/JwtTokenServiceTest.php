<?php

declare(strict_types = 1);

namespace Tests\Feature\Jwt;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\IssuedAccessToken;
use SineMacula\Laravel\Authentication\Jwt\JwtKeyring;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use Tests\Concerns\InspectsIssuanceGuards;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Concerns\PretendsStorageEngines;
use Tests\Integration\Fixtures\SeparateConnectionSession;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainSessionFixture;
use Tests\Unit\Stubs\StubBareSession;
use Tests\Unit\Stubs\StubIdentity;
use Tests\Unit\Stubs\StubNonModelSession;

/**
 * Feature tests of how the token service issues an access token for a stored
 * session: in a transaction on the session's connection that first writes the
 * session's issuance guard, then takes the issue time, then reads the session's
 * proofs current, so the token's `auth_time` and `amr` never go back on those
 * of a token of the session committed before it; and how the package's own
 * issuers, which write the session's row themselves, issue without the guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IssuedAccessToken::class)]
#[CoversClass(JwtTokenService::class)]
final class JwtTokenServiceTest extends TestCase
{
    use InspectsIssuanceGuards, InteractsWithProofs, InteractsWithSessionRecords, PretendsStorageEngines;

    /** @var string The secret the test keyring signs with. */
    private const string SECRET = 'test-secret-key-with-at-least-32-bytes!';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freezeAt(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        $this->now = CarbonImmutable::now();
    }

    /**
     * Release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * The token is issued in a transaction of its own: the session's issuance
     * guard is its first statement, the read of the session's proofs comes
     * after it in the same transaction, and the token carries what they say.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenForASessionWritesItsGuardFirstInItsOwnTransaction(): void
    {
        $session           = $this->storedSession();
        [$queries, $token] = self::recordQueries(fn (): Secret => self::tokens()->issueAccessToken(self::identity(), self::principal(), null, $session));

        self::assertCount(2, $queries);
        self::assertStringStartsWith('update', $queries[0][0]);
        self::assertStringContainsString('issuance_sequence', $queries[0][0]);
        self::assertStringContainsString('group by', $queries[1][0]);
        self::assertSame([1, 1], array_column($queries, 1));
        self::assertSame(0, DB::transactionLevel());
        self::assertSame(1, self::issuanceGuardWrites($session->getKey()));

        $claims = self::tokens()->parse($token?->reveal() ?? '', TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame($session->getKey(), $claims['sid']);
        self::assertSame($this->now->getTimestamp(), $claims['auth_time']);
        self::assertSame(['pwd'], $claims['amr']);
    }

    /**
     * Inside a caller's transaction the token's transaction is a savepoint of
     * it, so the guard is held until the caller ends, and rolled back with it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testInsideACallersTransactionTheGuardIsHeldAndRolledBackWithIt(): void
    {
        $session = $this->storedSession();

        DB::beginTransaction();

        [$queries] = self::recordQueries(fn (): Secret => self::tokens()->issueAccessToken(self::identity(), self::principal(), null, $session));

        self::assertSame([2, 2], array_column($queries, 1));
        self::assertSame(1, self::issuanceGuardWrites($session->getKey()));

        DB::rollBack();

        self::assertSame(0, self::issuanceGuardWrites($session->getKey()));
    }

    /**
     * With no issue time given, the token is issued at the second the guard was
     * written, not when the call began: a proof another issuer committed while
     * the guard waited is never later than the token's `iat`. A time the caller
     * gives is kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDefaultIssueTimeIsTakenOnceTheGuardIsWritten(): void
    {
        $session = $this->storedSession();
        $later   = $this->now->addSeconds(3);

        DB::listen(function (QueryExecuted $query) use ($later): void {
            if (!str_contains($query->sql, 'issuance_sequence')) {
                return;
            }

            $this->freezeAt($later);
        });

        $defaulted = self::tokens()->parse(self::tokens()->issueAccessToken(self::identity(), self::principal(), null, $session)->reveal(), TokenType::ACCESS);
        $given     = self::tokens()->parse(self::tokens()->issueAccessToken(self::identity(), self::principal(), null, $session, $this->now)->reveal(), TokenType::ACCESS);

        self::assertIsArray($defaulted);
        self::assertIsArray($given);
        self::assertSame($later->getTimestamp(), $defaulted['iat']);
        self::assertSame($this->now->getTimestamp(), $given['iat']);
        self::assertSame(2, self::issuanceGuardWrites($session->getKey()));
    }

    /**
     * A session model off the storage connection is refused before anything is
     * read or written, as the session lookup refuses one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionModelOffTheStorageConnectionIsRefused(): void
    {
        config()->set('database.connections.' . SeparateConnectionSession::CONNECTION, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);

        $session   = (new SeparateConnectionSession)->forceFill([...self::liveSession(), 'id' => '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70']);
        [$queries] = self::recordQueries(static function () use ($session): void {
            try {
                self::tokens()->issueAccessToken(self::identity(), self::principal(), null, $session);

                self::fail('A session off the storage connection was issued a token.');
            } catch (InvalidSessionModelConfigurationException $exception) {
                self::assertStringContainsString(SeparateConnectionSession::class, $exception->getMessage());
            }
        });

        self::assertCount(0, $queries);
    }

    /**
     * A session whose row is gone is a `LogicException`: the guard writes no
     * row, so its proofs are never read and its transaction is rolled back.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionWithoutARowIsALogicError(): void
    {
        $session = $this->storedSession();

        DB::table('authentication_sessions')->where('id', $session->getKey())->delete();

        [$queries] = self::recordQueries(static function () use ($session): void {
            try {
                self::tokens()->issueAccessToken(self::identity(), self::principal(), null, $session);

                self::fail('A session without a row was issued a token.');
            } catch (\LogicException $exception) {
                self::assertSame('The session\'s row no longer exists, so its issuance guard cannot be written.', $exception->getMessage());
            }
        });

        self::assertCount(1, $queries);
        self::assertSame(0, DB::transactionLevel());
    }

    /**
     * The package's own issuers, which write the session's row themselves
     * first, issue at the time they give without writing anything, reading the
     * proofs as the public issue does, and are told when the token expires and
     * how long it lives as its `exp` and `iat` say; a machine is refused, as it
     * has no session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardedIssueWritesNothingAndRefusesAMachine(): void
    {
        $session           = $this->storedSession();
        $issuedAt          = $this->now->addSecond()->addMilliseconds(400);
        $issued            = null;
        [$queries, $token] = self::recordQueries(static function () use ($session, $issuedAt, &$issued): Secret {
            $issued = self::tokens()->issueGuardedAccessToken(self::identity(), self::principal(), null, $session, $issuedAt);

            return $issued->token;
        });

        self::assertCount(1, $queries);
        self::assertStringContainsString('group by', $queries[0][0]);
        self::assertSame(0, self::issuanceGuardWrites($session->getKey()));

        $claims = self::tokens()->parse($token?->reveal() ?? '', TokenType::ACCESS);

        self::assertIsArray($claims);
        self::assertSame($this->now->addSecond()->getTimestamp(), $claims['iat']);
        self::assertSame($this->now->getTimestamp(), $claims['auth_time']);
        self::assertInstanceOf(IssuedAccessToken::class, $issued);
        self::assertIsInt($claims['exp']);
        self::assertSame($claims['exp'], $issued->expiresAt->getTimestamp());
        self::assertSame([$claims['exp'] - $this->now->addSecond()->getTimestamp(), 15 * 60], [$issued->expiresIn, $issued->expiresIn]);

        $machine = \Mockery::mock(MachineIdentity::class);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A non-human identity has no session');

        self::tokens()->issueGuardedAccessToken($machine, self::principal(), null, $session, $this->now);
    }

    /**
     * A guarded issue reads the proofs current, with a shared lock on MySQL and
     * MariaDB, unless the issuer's transaction inserted the session, whose
     * proofs are its own until it commits; other engines never lock.
     *
     * @param  string  $driver
     * @return void
     */
    #[DataProvider('provideStorageEngines')]
    public function testAGuardedIssueReadsCurrentUnlessTheSessionIsNew(string $driver): void
    {
        $issue = fn (bool $inserted): \Closure => function () use ($inserted): void {
            $session = (new Session)->forceFill([...self::liveSession(), 'id' => '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70']);

            self::assertHasNoClaims(fn (): IssuedAccessToken => $inserted
                ? self::tokens()->issueGuardedAccessToken(self::identity(), self::principal(), null, $session, $this->now, true)
                : self::tokens()->issueGuardedAccessToken(self::identity(), self::principal(), null, $session, $this->now));
        };

        $current  = self::statementsOn($driver, $issue(false));
        $inserted = self::statementsOn($driver, $issue(true));

        self::assertCount(1, $current);
        self::assertCount(1, $inserted);
        self::assertSame(in_array($driver, ['mysql', 'mariadb'], true), str_ends_with($current[0], ' lock in share mode'));
        self::assertStringEndsNotWith(' lock in share mode', $inserted[0]);
    }

    /**
     * A session that is not an Eloquent model takes no guard and no
     * transaction, and its proofs are read current too; it records no owner a
     * proof could be bound to, so no token is issued for it.
     *
     * @return void
     */
    public function testASessionThatIsNotAModelIsReadCurrentWithoutAGuard(): void
    {
        $session    = new PlainSessionFixture('0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f70', $this->now->addHour(), $this->now->addDay());
        $statements = self::statementsOn('mysql', static function () use ($session): void {
            self::assertHasNoClaims(static fn (): Secret => self::tokens()->issueAccessToken(self::identity(), self::principal(), null, $session));
        });

        self::assertCount(1, $statements);
        self::assertStringEndsWith(' lock in share mode', $statements[0]);
    }

    /**
     * A session that declares the Eloquent session contract but is not a model
     * is issued for as any other session that is not one: no guard, no
     * transaction, and its proofs read current; only a session that is both
     * takes the guarded path.
     *
     * @return void
     */
    public function testAnEloquentSessionThatIsNotAModelIsReadCurrentWithoutAGuard(): void
    {
        $session = \Mockery::mock(StubNonModelSession::class);
        $session->shouldReceive('getSessionIdentifier')->andReturn('0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f71');
        $session->shouldReceive('getIdleExpiresAt')->andReturn($this->now->addHour());
        $session->shouldReceive('getAbsoluteExpiresAt')->andReturn($this->now->addDay());
        $session->shouldReceive('getTenantId')->andReturnNull();
        $session->shouldReceive('getGuard')->andReturn('api');

        $statements = self::statementsOn('mysql', static function () use ($session): void {
            self::assertHasNoClaims(static fn (): Secret => self::tokens()->issueAccessToken(self::identity(), self::principal(), null, $session));
        });

        self::assertCount(1, $statements);
        self::assertStringEndsWith(' lock in share mode', $statements[0]);
        self::assertSame(0, DB::transactionLevel());
    }

    /**
     * A model that implements only the session contract, not the Eloquent one,
     * is issued for as a session that is not a model: it is never held to the
     * storage connection, no guard is written and no transaction opened, so it
     * is refused for its own deadlines, without a query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAModelThatIsOnlyASessionIsIssuedForWithoutAGuard(): void
    {
        $session    = new StubBareSession(['id' => '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f72']);
        $statements = [];
        $refusal    = null;

        DB::listen(static function (QueryExecuted $query) use (&$statements): void {
            $statements[] = $query->sql;
        });

        try {
            self::tokens()->issueAccessToken(self::identity(), self::principal(), null, $session);
        } catch (\InvalidArgumentException $exception) {
            $refusal = $exception->getMessage();
        }

        self::assertSame('Cannot issue a token for a session that has ended or that has no idle deadline.', $refusal);
        self::assertSame([], $statements);
        self::assertSame(0, DB::transactionLevel());
    }

    /**
     * A session of the package's model, stored with its sign-in's first factor
     * now.
     *
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function storedSession(): Session
    {
        $session = new Session;

        $session->forceFill([...self::liveSession(), 'authenticatable_type' => StubIdentity::class, 'authenticatable_id' => '1'])->save();

        self::recordProof($session, ProofKind::FIRST_FACTOR, $this->now, ['pwd']);

        return $session;
    }

    /**
     * Run the issue and return the statements it ran, each with the transaction
     * level it ran at, and the token it issued, if any.
     *
     * @param  \Closure(): mixed  $issue
     * @return array{0: list<array{0: string, 1: int}>, 1: ?\SineMacula\Laravel\Authentication\Secrets\Secret}
     */
    private static function recordQueries(\Closure $issue): array
    {
        $queries = [];

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries[] = [$query->sql, $query->connection->transactionLevel()];
        });

        $token = $issue();

        return [$queries, $token instanceof Secret ? $token : null];
    }

    /**
     * Assert the issue finds no counting first factor, as a pretended read of
     * no rows does.
     *
     * @param  \Closure(): mixed  $issue
     * @return void
     */
    private static function assertHasNoClaims(\Closure $issue): void
    {
        try {
            $issue();
        } catch (\LogicException $exception) {
            self::assertStringContainsString('no counting first factor', $exception->getMessage());

            return;
        }

        self::fail('A session with no proofs was issued a token.');
    }

    /**
     * The token service under test.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private static function tokens(): JwtTokenService
    {
        return new JwtTokenService(
            JwtKeyring::fromKeyMap(['test-kid' => self::SECRET], 'test-kid', 'HS256'),
            'api',
            new TokenLifetimes(15, 60 * 24 * 30, 60 * 24 * 180, 30),
            30,
            'https://issuer.example.test',
            'https://api.example.test',
        );
    }

    /**
     * An identity whose identifier is `identity-7`.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private static function identity(): Identity
    {
        $identity = \Mockery::mock(Identity::class);
        $identity->shouldReceive('getAuthIdentifier')->andReturn('identity-7');

        return $identity;
    }

    /**
     * A principal whose identifier is `principal-3`, acting in no tenant.
     *
     * @return \SineMacula\Laravel\Authentication\Contracts\Principal
     */
    private static function principal(): Principal
    {
        $principal = \Mockery::mock(Principal::class);
        $principal->shouldReceive('getPrincipalIdentifier')->andReturn('principal-3');
        $principal->shouldReceive('getTenant')->andReturnNull();

        return $principal;
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
