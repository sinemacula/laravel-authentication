<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Failed;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Refreshed;
use SineMacula\Laravel\Authentication\Events\SessionAuthenticated;
use SineMacula\Laravel\Authentication\Events\SessionCreated;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\RefreshRotationStore;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Sessions\AdmissionRecheck;
use SineMacula\Laravel\Authentication\Sessions\SessionSwitch;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Fixtures\Sessions\GuardSessions;
use Tests\Integration\Fixtures\SeparateConnectionCutoffIdentity;
use Tests\Integration\Fixtures\SeparateConnectionSession;
use Tests\Integration\Fixtures\SeparateConnectionSessionIdentity;
use Tests\TestCase;

/**
 * End-to-end tests for a session model kept on its own connection, apart from
 * the identities: refresh and the bearer path read and write the session on
 * that connection, every issuance runs in a transaction on it, and a replay
 * revocation is reported once it is committed there, whatever a transaction on
 * another connection does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionRevoked::class)]
#[CoversClass(JwtGuard::class)]
#[CoversClass(JwtTokenService::class)]
#[CoversClass(RefreshTokenExchange::class)]
#[CoversClass(RefreshRotationStore::class)]
#[CoversClass(SessionSwitch::class)]
#[CoversClass(AdmissionRecheck::class)]
final class SeparateSessionConnectionIntegrationTest extends TestCase
{
    use InteractsWithSessionRecords;

    /** @var string The guard over identities that record a "tokens valid after" cutoff. */
    private const string CUTOFFS = 'cutoffs';

    /** @var string Plaintext rotation id of the session's first refresh token. */
    private const string ROTATION_ID = 'first-rotation-id';

    /** @var \Carbon\Carbon Frozen clock reference. */
    private Carbon $now;

    /** @var \ArrayObject<int, string> Names of the refresh outcome events, in dispatch order. */
    private \ArrayObject $dispatched;

    /**
     * Freeze the clocks, create the identity table on the default connection
     * (the shipped migrations created the session table on the storage
     * connection), record the refresh outcome events, and register a route
     * behind the `auth` middleware.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);
        JWT::$timestamp = $this->now->getTimestamp();

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $this->dispatched = new \ArrayObject;

        $dispatched = $this->dispatched;

        Event::listen([SessionRevoked::class, AuthenticationFailed::class, Failed::class, Refreshed::class], static function (object $event) use ($dispatched): void {
            $dispatched->append(class_basename($event));
        });

        Route::middleware('auth:api')->get('/me', static fn (): array => ['session' => Auth::session()?->getSessionIdentifier()]);
    }

    /**
     * Release the frozen clocks and drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('cutoff_identities');
        Schema::dropIfExists('stub_principals');

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();
        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * A refresh rotates the session on its own connection, the new access token
     * authenticates through the `auth` middleware, and the default connection
     * has no sessions table at all.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefreshAndBearerUseTheSessionsOwnConnection(): void
    {
        [$identity, $session] = $this->signIn();

        $pair = GuardSessions::of($this->guard())->refresh($this->tokens()->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal())->session?->tokens;

        self::assertNotNull($pair);
        self::assertSame(RefreshTokenHasher::hash(RefreshTokenHasher::successor(self::ROTATION_ID)), $this->row($session)['refresh_key']);
        self::assertSame(RefreshTokenHasher::hash(self::ROTATION_ID), $this->row($session)['previous_refresh_key']);

        $this->withHeaders(['Authorization' => 'Bearer ' . $pair->accessToken->reveal()])->getJson('/me')->assertOk()->assertJson(['session' => $session->id]);

        self::assertFalse(Schema::hasTable('authentication_sessions'));
    }

    /**
     * A replay revokes the session on its own connection, which commits at
     * once, so `SessionRevoked` is dispatched at once, before `Failed` and
     * `AuthenticationFailed`, even inside a transaction on the default
     * connection; that transaction rolling back neither undoes the revocation
     * nor withdraws the event.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testReplayIsReportedAtOnceWhateverAnotherConnectionsTransactionDoes(): void
    {
        $replay = $this->replayableToken();

        DB::beginTransaction();

        self::assertNull(GuardSessions::of($this->guard())->refresh($replay)->session);
        self::assertSame(['SessionRevoked', 'Failed', 'AuthenticationFailed'], $this->dispatched->getArrayCopy());

        DB::rollBack();

        self::assertSame(['SessionRevoked', 'Failed', 'AuthenticationFailed'], $this->dispatched->getArrayCopy());
        self::assertSame('rotation_reuse', $this->row($this->record())['revoked_reason']);
    }

    /**
     * Inside a transaction on the session's own connection the revocation is
     * reported only when that transaction commits, after `Failed` and
     * `AuthenticationFailed`, and never when it is rolled back, which also
     * leaves the session live.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testReplayInsideTheSessionConnectionsTransactionIsReportedOnItsCommit(): void
    {
        $replay     = $this->replayableToken();
        $connection = DB::connection(SeparateConnectionSession::CONNECTION);

        $connection->beginTransaction();

        self::assertNull(GuardSessions::of($this->guard())->refresh($replay)->session);

        $connection->rollBack();

        self::assertSame(['Failed', 'AuthenticationFailed'], $this->dispatched->getArrayCopy());
        self::assertNull($this->row($this->record())['revoked_at']);

        $this->dispatched->exchangeArray([]);

        $connection->beginTransaction();

        self::assertNull(GuardSessions::of($this->guard())->refresh($replay)->session);
        self::assertSame(['Failed', 'AuthenticationFailed'], $this->dispatched->getArrayCopy());

        $connection->commit();

        self::assertSame(['Failed', 'AuthenticationFailed', 'SessionRevoked'], $this->dispatched->getArrayCopy());
        self::assertSame('rotation_reuse', $this->row($this->record())['revoked_reason']);
    }

    /**
     * A revocation made inside a nested transaction on the session's own
     * connection that is rolled back is never reported, even though the outer
     * transaction then commits, and the session stays live.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testReplayRolledBackWithANestedTransactionIsNeverReported(): void
    {
        $replay     = $this->replayableToken();
        $connection = DB::connection(SeparateConnectionSession::CONNECTION);

        $connection->beginTransaction();
        $connection->beginTransaction();

        self::assertNull(GuardSessions::of($this->guard())->refresh($replay)->session);

        $connection->rollBack();
        $connection->commit();

        self::assertSame(['Failed', 'AuthenticationFailed'], $this->dispatched->getArrayCopy());
        self::assertNull($this->row($this->record())['revoked_at']);
    }

    /**
     * A refresh is reported once its rotation is committed on the session's own
     * connection: at once while only another connection has a transaction open,
     * and that transaction rolling back does not withdraw it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testRefreshIsReportedAtOnceWhateverAnotherConnectionsTransactionDoes(): void
    {
        [$identity, $session] = $this->signIn();

        DB::beginTransaction();

        self::assertNotNull(GuardSessions::of($this->guard())->refresh($this->tokens()->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal())->session);
        self::assertSame(['Refreshed'], $this->dispatched->getArrayCopy());

        DB::rollBack();

        self::assertSame(['Refreshed'], $this->dispatched->getArrayCopy());
    }

    /**
     * Inside a transaction on the session's own connection a refresh is
     * reported only when that transaction commits, and never when it rolls
     * back, which also leaves the presented token current.
     *
     * @return void
     *
     * @throws \Random\RandomException
     * @throws \Throwable
     */
    public function testRefreshInsideTheSessionConnectionsTransactionIsReportedOnItsCommit(): void
    {
        [$identity, $session] = $this->signIn();

        $token      = $this->tokens()->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();
        $connection = DB::connection(SeparateConnectionSession::CONNECTION);

        $connection->beginTransaction();

        self::assertNotNull(GuardSessions::of($this->guard())->refresh($token)->session);

        $connection->rollBack();

        self::assertSame([], $this->dispatched->getArrayCopy());
        self::assertSame(RefreshTokenHasher::hash(self::ROTATION_ID), $this->row($session)['refresh_key']);

        $connection->beginTransaction();

        self::assertNotNull(GuardSessions::of($this->guard())->refresh($token)->session);
        self::assertSame([], $this->dispatched->getArrayCopy());

        $connection->commit();

        self::assertSame(['Refreshed'], $this->dispatched->getArrayCopy());
    }

    /**
     * A refresh opens its transaction on the session's own connection, not the
     * default one: the issuance guard, the re-read and the rotation all run
     * inside it.
     *
     * @return void
     */
    public function testARefreshRunsInATransactionOnTheSessionsOwnConnection(): void
    {
        [$identity, $session] = $this->signIn();

        $token      = $this->tokens()->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();
        $statements = $this->statementsOf(fn (): mixed => GuardSessions::of($this->guard())->refresh($token)->session);

        self::assertIssuedInATransactionOnTheSessionsConnection($statements, 'refresh_rotated_at');
    }

    /**
     * A switch opens its transaction on the session's own connection, not the
     * default one: the issuance guard, the re-read and the compare-and-swap all
     * run inside it.
     *
     * @return void
     */
    public function testASwitchRunsInATransactionOnTheSessionsOwnConnection(): void
    {
        [$identity, $session] = $this->signIn();

        $token      = $this->tokens()->issueRefreshToken($session, self::ROTATION_ID, $identity)->reveal();
        $statements = $this->statementsOf(fn (): mixed => GuardSessions::of($this->guard())->switchTo($token, SwitchTarget::tenant(TenantSelection::none()))->session);

        self::assertIssuedInATransactionOnTheSessionsConnection($statements, 'refresh_rotated_at');
    }

    /**
     * An access token issued for the session opens its transaction on the
     * session's own connection, not the default one: the issuance guard and the
     * read of the session's proofs run inside it.
     *
     * @return void
     */
    public function testAnAccessTokenIsIssuedInATransactionOnTheSessionsOwnConnection(): void
    {
        [$identity, $session] = $this->signIn();

        $statements = $this->statementsOf(fn (): mixed => $this->tokens()->issueAccessToken($identity, $identity, null, $session));

        self::assertIssuedInATransactionOnTheSessionsConnection($statements, 'group by');
    }

    /**
     * A sign-in made inside a transaction on the identity's connection, with
     * the sessions on their own, commits its session at once and binds the
     * guard to it, while the check of what it acts as waits for that
     * transaction to end, and the events that report the session with it:
     * when it rolls back, the check still runs and the session is reported;
     * when it commits the identity's deletion made in it, the check ends the
     * session, which the caller holds, and reports that instead.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInInsideATransactionOnTheIdentitysConnectionIsCheckedWhenThatTransactionEnds(): void
    {
        $identity            = new SeparateConnectionSessionIdentity;
        $identity->email     = 'checked@example.test';
        $identity->password  = app(Hasher::class)->make('correct horse battery staple');
        $identity->is_active = true;
        $identity->save();

        $credentials = ['email' => 'checked@example.test', 'password' => 'correct horse battery staple'];
        /** @var \ArrayObject<int, string> $reported */
        $reported = new \ArrayObject;

        Event::listen([SessionAuthenticated::class, SessionCreated::class, SignedIn::class, SessionRevoked::class], static function (object $event) use ($reported): void {
            $reported->append(class_basename($event));
        });

        DB::beginTransaction();

        $kept = Auth::sessions()->signIn('password', $credentials)->session;

        self::assertNotNull($kept);
        self::assertSame(['SessionAuthenticated'], $reported->getArrayCopy());

        DB::rollBack();

        self::assertSame(['SessionAuthenticated', 'SessionCreated', 'SignedIn'], $reported->getArrayCopy());
        self::assertNull(self::revokedReasonOf($kept->record->getKey()));

        $reported->exchangeArray([]);

        DB::beginTransaction();

        $ended = Auth::sessions()->signIn('password', $credentials)->session;

        self::assertNotNull($ended);

        SeparateConnectionSessionIdentity::query()->whereKey($identity->getKey())->delete();

        DB::commit();

        self::assertSame(['SessionAuthenticated', 'SessionRevoked'], $reported->getArrayCopy());
        self::assertSame('identity_deleted', self::revokedReasonOf($ended->record->getKey()));
        $guard = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $guard);
        self::assertNull($guard->session());
    }

    /**
     * With the sessions on their own connection, a session committed and bound
     * at once whose check ends it when the identity's transaction commits its
     * deletion leaves the guard with nothing bound, even when a listener of the
     * revocation throws and the caller catches it: the session is revoked and
     * the guard has forgotten its identity, principal and session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAGuardForgetsASessionItsCheckEndsThoughTheRevocationsListenerThrows(): void
    {
        $identity            = new SeparateConnectionSessionIdentity;
        $identity->email     = 'thrown@example.test';
        $identity->password  = app(Hasher::class)->make('correct horse battery staple');
        $identity->is_active = true;
        $identity->save();

        $guard = app('auth')->guard('api');

        self::assertInstanceOf(JwtGuard::class, $guard);

        DB::beginTransaction();

        $ended = Auth::sessions()->signIn('password', ['email' => 'thrown@example.test', 'password' => 'correct horse battery staple'])->session;

        self::assertNotNull($ended);
        self::assertSame($ended->record->getKey(), $guard->session()?->getSessionIdentifier());

        SeparateConnectionSessionIdentity::query()->whereKey($identity->getKey())->delete();

        Event::listen(SessionRevoked::class, static function (): void {
            throw new \RuntimeException('listener');
        });

        try {
            DB::commit();

            self::fail('Expected the listener to throw.');
        } catch (\RuntimeException $exception) {
            self::assertSame('listener', $exception->getMessage());
        }

        self::assertSame('identity_deleted', self::revokedReasonOf($ended->record->getKey()));
        self::assertNull($guard->session());
        self::assertNull($guard->principal());
        self::assertFalse($guard->check());
    }

    /**
     * A password change that keeps the session a sign-in wrote inside a
     * transaction on the identity's connection, made a second after the sign-in
     * began and before that transaction commits, leaves the session standing:
     * its check, which waits for that transaction, does not take the cutoff the
     * change moved for a revocation that could not see the session, so the
     * session stays live and the guard stays bound to it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasswordChangeThatKeepsASessionCheckedAfterTheIdentitysTransactionLeavesItStanding(): void
    {
        Schema::create('cutoff_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email');
            $blueprint->string('password');
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
        });

        CarbonImmutable::setTestNow($this->now);

        $created  = SeparateConnectionCutoffIdentity::query()->create(['email' => 'kept@example.test', 'password' => app(Hasher::class)->make('correct horse battery staple')]);
        $identity = SeparateConnectionCutoffIdentity::query()->whereKey($created->getKey())->firstOrFail();
        $later    = CarbonImmutable::instance($this->now)->addSecond();

        DB::beginTransaction();

        $signedIn = Auth::sessions(self::CUTOFFS)->signIn('password', ['email' => 'kept@example.test', 'password' => 'correct horse battery staple'])->session;

        self::assertNotNull($signedIn);

        Carbon::setTestNow($later);
        CarbonImmutable::setTestNow($later);

        Auth::sessions(self::CUTOFFS)->passwordChanged($identity, $signedIn->record);

        DB::commit();

        self::assertSame($later->getTimestamp(), $identity->refresh()->getTokensValidAfter()?->getTimestamp());
        self::assertNull(self::revokedReasonOf($signedIn->record->getKey()));

        $guard = app('auth')->guard(self::CUTOFFS);

        self::assertInstanceOf(JwtGuard::class, $guard);
        self::assertSame($signedIn->record->getKey(), $guard->session()?->getSessionIdentifier());
    }

    /**
     * Keep the sessions on their own connection, a separate database, as the
     * storage connection, the counters on the default one, and configure the
     * `api` guard.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . SeparateConnectionSession::CONNECTION, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $config->set('authentication.storage.connection', SeparateConnectionSession::CONNECTION);
        $config->set('authentication.rate_limits.connection', 'testing');
        $config->set('authentication.session.model', SeparateConnectionSession::class);
        $config->set('auth.defaults.guard', 'api');
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => SeparateConnectionSessionIdentity::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities', 'application' => ['methods' => ['password']], 'jwt' => ['refresh_grace_seconds' => 30]]);
        $config->set('auth.providers.' . self::CUTOFFS, ['driver' => 'model', 'model' => SeparateConnectionCutoffIdentity::class]);
        $config->set('auth.guards.' . self::CUTOFFS, ['driver' => 'jwt', 'provider' => self::CUTOFFS, 'application' => ['methods' => ['password']]]);
    }

    /**
     * Why the session's row records it was revoked, if it was.
     *
     * @param  mixed  $id
     * @return mixed
     */
    private static function revokedReasonOf(mixed $id): mixed
    {
        return DB::connection(SeparateConnectionSession::CONNECTION)->table('authentication_sessions')->where('id', $id)->value('revoked_reason');
    }

    /**
     * Persist an identity signed in on a new session holding `ROTATION_ID`.
     *
     * @return array{0: \Tests\Integration\Fixtures\SeparateConnectionSessionIdentity, 1: \Tests\Integration\Fixtures\SeparateConnectionSession}
     */
    private function signIn(): array
    {
        $identity            = new SeparateConnectionSessionIdentity;
        $identity->email     = 'separate@example.test';
        $identity->password  = 'irrelevant';
        $identity->is_active = true;
        $identity->save();

        $session = new SeparateConnectionSession;
        $session->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'refresh_key'          => RefreshTokenHasher::hash(self::ROTATION_ID),
        ])->save();

        return [$identity, $session];
    }

    /**
     * Sign in, rotate the session's row past `ROTATION_ID` an hour ago, and
     * return a validly signed refresh token carrying `ROTATION_ID`, which is
     * now a replay.
     *
     * @return string
     *
     * @throws \Random\RandomException
     */
    private function replayableToken(): string
    {
        [$identity, $session] = $this->signIn();

        DB::connection(SeparateConnectionSession::CONNECTION)->table('authentication_sessions')->where('id', $session->id)->update([
            'refresh_key'          => RefreshTokenHasher::hash(RefreshTokenHasher::successor(self::ROTATION_ID)),
            'previous_refresh_key' => RefreshTokenHasher::hash(self::ROTATION_ID),
            'refresh_rotated_at'   => $this->now->copy()->subHour()->format('Y-m-d H:i:s'),
        ]);

        return $this->tokens()->issueRefreshToken($this->record(), self::ROTATION_ID, $identity)->reveal();
    }

    /**
     * Run the operation, asserting it returned something, and return each
     * statement it ran: its connection, that connection's transaction level and
     * the default connection's, and its SQL.
     *
     * @param  \Closure(): mixed  $operation
     * @return list<array{0: string, 1: int, 2: int, 3: string}>
     */
    private function statementsOf(\Closure $operation): array
    {
        /** @var \ArrayObject<int, array{0: string, 1: int, 2: int, 3: string}> $statements */
        $statements = new \ArrayObject;

        Event::listen(QueryExecuted::class, static function (QueryExecuted $query) use ($statements): void {
            $statements->append([$query->connectionName, $query->connection->transactionLevel(), DB::connection()->transactionLevel(), $query->sql]);
        });

        self::assertNotNull($operation());

        return array_values($statements->getArrayCopy());
    }

    /**
     * Assert the issuance guard is written on the session's connection, and
     * that it and every statement on that connection up to the last one whose
     * SQL holds the marker run inside one transaction there, while the default
     * connection never opens one.
     *
     * @param  list<array{0: string, 1: int, 2: int, 3: string}>  $statements
     * @param  string  $last
     * @return void
     */
    private static function assertIssuedInATransactionOnTheSessionsConnection(array $statements, string $last): void
    {
        $sql   = array_column($statements, 3);
        $guard = array_key_first(array_filter($sql, static fn (string $statement): bool => str_starts_with($statement, 'update') && str_contains($statement, 'issuance_sequence')));
        $end   = array_key_last(array_filter($sql, static fn (string $statement): bool => str_contains($statement, $last)));

        self::assertIsInt($guard);
        self::assertIsInt($end);
        self::assertGreaterThan($guard, $end);
        self::assertSame(SeparateConnectionSession::CONNECTION, $statements[$guard][0]);

        $held = array_filter(array_slice($statements, $guard, $end - $guard + 1), static fn (array $statement): bool => $statement[0] === SeparateConnectionSession::CONNECTION);

        self::assertSame([1], array_values(array_unique(array_column($held, 1))));
        self::assertSame([0], array_values(array_unique(array_column($statements, 2))));
        self::assertSame(0, DB::connection(SeparateConnectionSession::CONNECTION)->transactionLevel());
    }

    /**
     * The one session, loaded from its own connection.
     *
     * @return \Tests\Integration\Fixtures\SeparateConnectionSession
     */
    private function record(): SeparateConnectionSession
    {
        return SeparateConnectionSession::query()->sole();
    }

    /**
     * Read a session's raw row from its own connection.
     *
     * @param  \Tests\Integration\Fixtures\SeparateConnectionSession  $session
     * @return array<string, mixed>
     */
    private function row(SeparateConnectionSession $session): array
    {
        return (array) DB::connection(SeparateConnectionSession::CONNECTION)->table('authentication_sessions')->where('id', $session->id)->first();
    }

    /**
     * The `api` guard's token service.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function tokens(): JwtTokenService
    {
        $tokens = Auth::jwt('api');

        self::assertNotNull($tokens);

        return $tokens;
    }

    /**
     * A fresh `api` guard.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guard(): JwtGuard
    {
        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $manager->forgetGuards();

        $guard = $manager->guard('api');

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
