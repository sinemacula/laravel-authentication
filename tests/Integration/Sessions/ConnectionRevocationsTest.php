<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\SessionRevoked;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Sessions\ConnectionRevocations;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithFoldingCollations;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\CutoffIdentity;
use Tests\TestCase;

/**
 * Integration tests of the revocations by connection and by link against real
 * rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionRevocations::class)]
final class ConnectionRevocationsTest extends TestCase
{
    use InteractsWithFoldingCollations, InteractsWithSessions;

    /** @var string The frozen time every revocation happens at. */
    private const string NOW = '2027-01-15 10:00:00';

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(CarbonImmutable::parse(self::NOW));
        CarbonImmutable::setTestNow(CarbonImmutable::parse(self::NOW));

        $this->createSessionTables();

        Schema::create('cutoff_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Release the clocks and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('cutoff_identities');

        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        parent::tearDown();
    }

    /**
     * Every session past one chunk is revoked once.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEverySessionPastOneChunkIsRevokedOnce(): void
    {
        $ada   = $this->seedCutoffIdentity('ada@example.test');
        $grace = $this->seedCutoffIdentity('grace@example.test');

        $this->insertSessions($ada, 'conn-a', 300);
        $this->insertSessions($grace, 'conn-a', ConnectionRevocations::CHUNK - 300 + 1);
        $this->insertSessions($ada, 'conn-b', 3);

        $reported = $this->countRevocations();

        self::assertSame(ConnectionRevocations::CHUNK + 1, Auth::sessions('api')->connectionDisabled('conn-a'));
        self::assertSame(ConnectionRevocations::CHUNK + 1, DB::table('authentication_sessions')->where('revoked_reason', 'connection_disabled')->count());
        self::assertSame(3, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
        self::assertCount(ConnectionRevocations::CHUNK + 1, $reported);
        self::assertSame(0, Auth::sessions('api')->connectionDisabled('conn-a'));
    }

    /**
     * A link past one chunk of the identity's sessions revokes only those
     * through it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkPastOneChunkOfTheIdentitysSessionsRevokesOnlyThoseThroughIt(): void
    {
        $ada   = $this->seedCutoffIdentity('ada@example.test');
        $grace = $this->seedCutoffIdentity('grace@example.test');

        $this->insertSessions($ada, 'conn-b', ConnectionRevocations::CHUNK);
        $this->insertSessions($ada, 'conn-a', 2);
        $this->insertSessions($ada, 'conn-a', 2, 'link-2');
        $this->insertSessions($ada, 'conn-a', 1, null);
        $this->insertSessions($ada, null, 2);
        $this->insertSessions($grace, 'conn-a', 2);

        self::assertSame(2, Auth::sessions('api')->linkRemoved($ada, 'conn-a', 'link-1'));
        self::assertSame(2, DB::table('authentication_sessions')->where('revoked_reason', 'link_removed')->count());
        self::assertSame(ConnectionRevocations::CHUNK + 7, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
        self::assertNull(DB::table('cutoff_identities')->where('id', $ada->getKey())->value('tokens_valid_after'));
    }

    /**
     * A widened link scope past one chunk is mandatory and idempotent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAWidenedLinkScopePastOneChunkIsMandatoryAndIdempotent(): void
    {
        config()->set('authentication.revocation', ['connection_disabled' => false, 'connection_deleted' => false, 'link_removed' => false]);

        $ada = $this->seedCutoffIdentity('ada@example.test');

        $this->insertSessions($ada, 'conn-a', ConnectionRevocations::CHUNK, 'link-2');
        $this->insertSessions($ada, 'conn-a', 3);

        $reported = $this->countRevocations();

        self::assertSame(3, Auth::sessions('api')->linkScopeWidened($ada, 'conn-a', 'link-1'));
        self::assertSame(3, DB::table('authentication_sessions')->where('revoked_reason', 'link_scope_widened')->count());
        self::assertCount(3, $reported);
        self::assertSame(0, Auth::sessions('api')->linkScopeWidened($ada, 'conn-a', 'link-1'));
        self::assertCount(3, $reported);
        self::assertSame(0, Auth::sessions('api')->linkRemoved($ada, 'conn-a', 'link-2'));
        self::assertSame(ConnectionRevocations::CHUNK, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
    }

    /**
     * A connection the collation counts as equal keeps its sessions.
     *
     * @param  string  $folded
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFoldedKeys')]
    public function testAConnectionTheCollationCountsAsEqualKeepsItsSessions(string $folded): void
    {
        self::foldColumns('authentication_provenance', ['connection_id']);

        $ada = $this->seedCutoffIdentity('ada@example.test');

        $this->insertSessions($ada, 'alice', 1);

        self::assertColumnFolds('authentication_provenance', 'connection_id', $folded);

        $this->insertSessions($ada, $folded, 2);

        self::assertSame(1, Auth::sessions('api')->connectionDisabled('alice'));
        self::assertSame(2, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
        self::assertSame(2, Auth::sessions('api')->connectionDeleted($folded));
        self::assertSame(0, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
    }

    /**
     * A link the collation counts as equal keeps its sessions.
     *
     * @param  string  $folded
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFoldedKeys')]
    public function testALinkTheCollationCountsAsEqualKeepsItsSessions(string $folded): void
    {
        self::foldColumns('authentication_provenance', ['connection_id']);
        self::foldColumns('authentication_provenance', ['link_id'], true);

        $ada = $this->seedCutoffIdentity('ada@example.test');

        $this->insertSessions($ada, 'alice', 1, 'alice');

        self::assertColumnFolds('authentication_provenance', 'connection_id', $folded);
        self::assertColumnFolds('authentication_provenance', 'link_id', $folded);

        $this->insertSessions($ada, $folded, 2, 'alice');
        $this->insertSessions($ada, 'alice', 3, $folded);

        self::assertSame(1, Auth::sessions('api')->linkRemoved($ada, 'alice', 'alice'));
        self::assertSame(5, DB::table('authentication_sessions')->whereNull('revoked_at')->count());
        self::assertSame(2, Auth::sessions('api')->linkScopeWidened($ada, $folded, 'alice'));
        self::assertSame(3, Auth::sessions('api')->linkRemoved($ada, 'alice', $folded));
    }

    /**
     * Rows of `[the trigger]`.
     *
     * @return iterable<string, array{0: \Closure(\Tests\Integration\Fixtures\CutoffIdentity): int}>
     */
    public static function provideTriggers(): iterable
    {
        yield 'a connection disabled' => [static fn (CutoffIdentity $identity): int => Auth::sessions('api')->connectionDisabled('conn-a')];
        yield 'a connection deleted' => [static fn (CutoffIdentity $identity): int => Auth::sessions('api')->connectionDeleted('conn-a')];
        yield 'a link removed' => [static fn (CutoffIdentity $identity): int => Auth::sessions('api')->linkRemoved($identity, 'conn-a', 'link-1')];
        yield 'a link scope widened' => [static fn (CutoffIdentity $identity): int => Auth::sessions('api')->linkScopeWidened($identity, 'conn-a', 'link-1')];
    }

    /**
     * A trigger rolls back with the caller's transaction.
     *
     * @param  \Closure(\Tests\Integration\Fixtures\CutoffIdentity): int  $trigger
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideTriggers')]
    public function testATriggerRollsBackWithTheCallersTransaction(\Closure $trigger): void
    {
        $identity = $this->seedCutoffIdentity('ada@example.test');

        $this->insertSessions($identity, 'conn-a', 2);

        $reported = $this->countRevocations();

        DB::beginTransaction();

        DB::table('cutoff_identities')->update(['email' => 'grace@example.test']);

        self::assertSame(2, $trigger($identity));

        DB::rollBack();

        self::assertSame('ada@example.test', DB::table('cutoff_identities')->value('email'));
        self::assertSame(0, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
        self::assertCount(0, $reported);
    }

    /**
     * A trigger commits with the caller's transaction and reports after it.
     *
     * @param  \Closure(\Tests\Integration\Fixtures\CutoffIdentity): int  $trigger
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideTriggers')]
    public function testATriggerCommitsWithTheCallersTransaction(\Closure $trigger): void
    {
        $identity = $this->seedCutoffIdentity('ada@example.test');

        $this->insertSessions($identity, 'conn-a', 2);

        $reported = $this->countRevocations();

        DB::transaction(static function () use ($trigger, $identity, $reported): void {

            DB::table('cutoff_identities')->update(['email' => 'grace@example.test']);

            self::assertSame(2, $trigger($identity));
            self::assertCount(0, $reported);
        });

        self::assertSame('grace@example.test', DB::table('cutoff_identities')->value('email'));
        self::assertSame(2, DB::table('authentication_sessions')->whereNotNull('revoked_at')->count());
        self::assertCount(2, $reported);
    }

    /**
     * Register the session guards, the `api` guard over identities that record
     * a cutoff.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('auth.providers.cutoff', ['driver' => 'model', 'model' => CutoffIdentity::class]);
        $config->set('auth.guards.api.provider', 'cutoff');
    }

    /**
     * Persist an identity that records no cutoff yet.
     *
     * @param  string  $email
     * @return \Tests\Integration\Fixtures\CutoffIdentity
     */
    private function seedCutoffIdentity(string $email): CutoffIdentity
    {
        $identity = new CutoffIdentity;
        $identity->forceFill(['email' => $email, 'password' => 'unused'])->save();

        return $identity;
    }

    /**
     * Insert live sessions of the identity, established through the connection
     * and link, or by password.
     *
     * @param  \Tests\Integration\Fixtures\CutoffIdentity  $identity
     * @param  ?string  $connection
     * @param  int  $count
     * @param  ?string  $link
     * @return void
     */
    private function insertSessions(CutoffIdentity $identity, ?string $connection, int $count, ?string $link = 'link-1'): void
    {
        $keys = array_map(static fn (): string => (string) Str::uuid7(), range(1, $count));

        $sessions = array_map(static fn (string $key): array => [
            'id'                   => $key,
            'generation'           => (string) Str::uuid7(),
            'authenticatable_type' => $identity->getMorphClass(),
            'authenticatable_id'   => IdentifierCoercion::stringify($identity->getKey()),
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => IdentifierCoercion::stringify($identity->getKey()),
            'status'               => 'active',
            'guard'                => 'api',
            'sign_in_method'       => $connection === null ? 'password' : 'external_provider',
            'refresh_key'          => hash('sha256', 'refresh-' . $key),
            'signed_in_at'         => '2027-01-15 09:00:00',
            'idle_expires_at'      => '2027-02-15 09:00:00',
            'absolute_expires_at'  => '2027-07-15 09:00:00',
        ], $keys);

        foreach (array_chunk($sessions, 200) as $chunk) {
            DB::table('authentication_sessions')->insert($chunk);
        }

        if ($connection === null) {
            return;
        }

        $provenance = array_map(static fn (string $key): array => ['session_id' => $key, 'connection_id' => $connection, 'link_id' => $link, 'created_at' => self::NOW], $keys);

        foreach (array_chunk($provenance, 200) as $chunk) {
            DB::table('authentication_provenance')->insert($chunk);
        }
    }

    /**
     * Count every `SessionRevoked` reported from now on.
     *
     * @return \ArrayObject<int, true>
     */
    private function countRevocations(): \ArrayObject
    {
        /** @var \ArrayObject<int, true> $reported */
        $reported = new \ArrayObject;

        Event::listen(SessionRevoked::class, static function () use ($reported): void {
            $reported->append(true);
        });

        return $reported;
    }
}
