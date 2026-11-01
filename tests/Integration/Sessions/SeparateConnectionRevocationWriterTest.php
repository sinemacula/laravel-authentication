<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Query\Builder;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Sessions\RevocationWriter;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Integration\Fixtures\SeparateConnectionCutoffIdentity;
use Tests\Integration\Fixtures\SeparateConnectionSession;
use Tests\TestCase;

/**
 * End-to-end tests of a bulk revocation whose sessions, pending ones among
 * them, live on their own connection, apart from the identity on the default
 * connection: the identity's cutoff moves on its connection first, then its
 * sessions end, active and pending alike, in one transaction on the session
 * connection, reported once that commits, and a failure there leaves the cutoff
 * moved and every session live.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevocationWriter::class)]
final class SeparateConnectionRevocationWriterTest extends TestCase
{
    use InteractsWithSessionRecords;

    /** @var string The frozen time every revocation happens at. */
    private const string NOW = '2027-01-15 10:00:00';

    /** @var \ArrayObject<int, string> Names of the revocation events, in dispatch order. */
    private \ArrayObject $dispatched;

    /**
     * Freeze the clock, create the identity table on the default connection and
     * the session table on the session connection, and record the revocation
     * events. The storage connection is set to the session connection once the
     * shipped migrations have run on the default one, so the test's own table
     * stands in for the shipped one there.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('authentication.storage.connection', SeparateConnectionSession::CONNECTION);

        CarbonImmutable::setTestNow(CarbonImmutable::parse(self::NOW));

        Schema::create('cutoff_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email');
            $blueprint->string('password');
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
        });

        self::createSessionRecordTable('authentication_sessions', 'id', SeparateConnectionSession::CONNECTION);

        $this->dispatched = new \ArrayObject;

        $dispatched = $this->dispatched;

        Event::listen([SessionRevoked::class, SignedOutEverywhere::class], static function (object $event) use ($dispatched): void {
            $dispatched->append(class_basename($event));
        });
    }

    /**
     * Release the clock and drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        Schema::dropIfExists('cutoff_identities');

        parent::tearDown();
    }

    /**
     * The sessions on the session connection end, the pending one among them,
     * the same table on the default connection is untouched, and the reports
     * come at once while only the identity's connection has a transaction open,
     * which rolling back neither undoes nor withdraws.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSessionConnectionHoldsTheRevocation(): void
    {
        $identity = $this->seedIdentity();

        $this->seedSession($identity);
        $this->seedSession($identity);
        $this->seedSession($identity, pending: true);

        DB::table('authentication_sessions')->insert([
            ...self::liveSession(),
            'id'                   => '0190e1a4-0000-7000-8000-000000000009',
            'generation'           => '0190e1a4-0000-7000-8000-00000000000a',
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->id,
        ]);

        DB::beginTransaction();

        self::assertSame(3, Auth::sessions('api')->passwordReset($identity));
        self::assertSame(['SessionRevoked', 'SessionRevoked', 'SessionRevoked', 'SignedOutEverywhere'], $this->dispatched->getArrayCopy());

        DB::rollBack();

        self::assertSame(3, $this->sessions()->where('revoked_reason', 'password_reset')->count());
        self::assertSame(1, $this->sessions()->where('status', 'pending')->where('revoked_reason', 'password_reset')->count());
        self::assertNull(DB::table('authentication_sessions')->value('revoked_at'));
    }

    /**
     * Inside a transaction on the session connection the revocation is reported
     * only when that transaction commits, and a rollback there undoes the
     * revocation of the active and the pending session alike and reports
     * nothing, while the identity's cutoff, written on its own connection,
     * stays moved.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheReportsWaitForTheSessionConnectionsCommit(): void
    {
        $identity   = $this->seedIdentity();
        $connection = DB::connection(SeparateConnectionSession::CONNECTION);

        $this->seedSession($identity);
        $this->seedSession($identity, pending: true);

        $connection->beginTransaction();

        self::assertSame(2, Auth::sessions('api')->revokeSessions($identity, RevocationReason::REVOKED));
        self::assertSame([], $this->dispatched->getArrayCopy());

        $connection->rollBack();

        self::assertSame([], $this->dispatched->getArrayCopy());
        self::assertSame(0, $this->sessions()->whereNotNull('revoked_at')->count());
        self::assertSame(self::NOW, $identity->fresh()?->getTokensValidAfter()?->format('Y-m-d H:i:s'));

        $connection->beginTransaction();

        self::assertSame(2, Auth::sessions('api')->revokeSessions($identity, RevocationReason::REVOKED));

        $connection->commit();

        self::assertSame(['SessionRevoked', 'SessionRevoked', 'SignedOutEverywhere'], $this->dispatched->getArrayCopy());
        self::assertSame(2, $this->sessions()->whereNotNull('revoked_at')->count());
    }

    /**
     * A failure in the session transaction after a session was revoked rolls
     * every revocation back and propagates, and leaves the identity's cutoff
     * moved: more is cut off, never less.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailingSessionTransactionLeavesTheCutoffMovedAndTheSessionsLive(): void
    {
        $identity = $this->seedIdentity();

        $this->seedSession($identity);
        $this->seedSession($identity, pending: true);

        $updates = 0;

        DB::connection(SeparateConnectionSession::CONNECTION)->beforeExecuting(static function (string $query) use (&$updates): void {
            if (str_starts_with($query, 'update') && ++$updates === 2) {
                throw new \RuntimeException('The second revocation failed.');
            }
        });

        try {
            Auth::sessions('api')->passwordChanged($identity);
            self::fail('The failing revocation was not reported.');
        } catch (\RuntimeException $exception) {
            self::assertSame('The second revocation failed.', $exception->getMessage());
        }

        self::assertSame(0, $this->sessions()->whereNotNull('revoked_at')->count());
        self::assertSame([], $this->dispatched->getArrayCopy());
        self::assertSame(self::NOW, $identity->fresh()?->getTokensValidAfter()?->format('Y-m-d H:i:s'));
    }

    /**
     * Keep the sessions on their own connection, and configure the `api` guard.
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

        $config->set('database.connections.' . SeparateConnectionSession::CONNECTION, ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => '']);
        $config->set('authentication.session.model', SeparateConnectionSession::class);
        $config->set('auth.defaults.guard', 'api');
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => SeparateConnectionCutoffIdentity::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities']);
    }

    /**
     * Persist an identity that records no cutoff yet.
     *
     * @return \Tests\Integration\Fixtures\SeparateConnectionCutoffIdentity
     */
    private function seedIdentity(): SeparateConnectionCutoffIdentity
    {
        return SeparateConnectionCutoffIdentity::query()->create(['email' => 'ada@example.test', 'password' => 'unused']);
    }

    /**
     * Persist a live session of the identity on the session connection, active
     * or pending.
     *
     * @param  \Tests\Integration\Fixtures\SeparateConnectionCutoffIdentity  $identity
     * @param  bool  $pending
     * @return void
     */
    private function seedSession(SeparateConnectionCutoffIdentity $identity, bool $pending = false): void
    {
        $state = $pending ? ['status' => 'pending', 'requires' => ['mfa'], 'pending_key' => str_repeat('b', 64), 'refresh_key' => null] : [];

        $session = new SeparateConnectionSession;
        $session->forceFill([
            ...self::liveSession('api', $identity),
            ...$state,
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => (string) $identity->id,
        ])->save();
    }

    /**
     * The sessions table on the session connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private function sessions(): Builder
    {
        return DB::connection(SeparateConnectionSession::CONNECTION)->table('authentication_sessions');
    }
}
