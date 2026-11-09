<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Sessions\ActiveSessionProofs;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\MarksSharedLocks;
use Tests\Fixtures\Proofs\UndescribedSignInProof;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainSessionFixture;
use Tests\Unit\Stubs\StubBareSession;
use Tests\Unit\Stubs\StubNonModelSession;

/**
 * Feature tests of the read of an active session's proofs and first factor that
 * the session service and a contribution subject make: one of the guard's live,
 * active sessions of a person, named by its key or given as the instance while
 * its key still holds it, answers its own counting proofs, filtered and bounded
 * as a pending session's are; every other session answers nothing, without
 * saying why, and with no proof read; and the session's row is locked, and its
 * proofs read current, only inside a transaction on the session model's
 * connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActiveSessionProofs::class)]
final class ActiveSessionProofsTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessions, MarksSharedLocks;

    /** @var string A second connection to the test database, with no package tables of its own. */
    private const string OTHER = 'other';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);
        CarbonImmutable::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();

        $this->createSessionTables();
    }

    /**
     * Close the second connection, drop the tables and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DB::disconnect(self::OTHER);

        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * An active session's counting proofs read newest first, by its key and by
     * its instance alike: never a voided proof or a further factor its adapter
     * refused, only those made at or after the time given (inclusive) and of
     * the kinds given when they are (none for no kinds), and no more than the
     * limit; its first factor is the oldest first-factor proof.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActiveSessionsCountingProofsAreRead(): void
    {
        $record = $this->signedIn()->record;
        $key    = $record->getKey();

        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinute(), ['otp'], new Evaluation(true, true));
        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinutes(2), ['otp'], new Evaluation(false, true));
        self::recordProof($record, ProofKind::RECOVERY_CODE, $this->now->addMinutes(3), [], new Evaluation(true, false));
        self::recordProof($record, ProofKind::FIRST_FACTOR_REAUTHENTICATION, $this->now->addMinutes(4), ['pwd']);
        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinutes(5), ['otp'], new Evaluation(true, true));

        DB::table('authentication_proofs')->where('authenticated_at', '>', $this->now->addMinutes(4))->update(['voided_at' => $this->now]);

        $expected = [ProofKind::FIRST_FACTOR_REAUTHENTICATION, ProofKind::RECOVERY_CODE, ProofKind::ADDITIONAL_FACTOR, ProofKind::FIRST_FACTOR];

        foreach ([$key, $record] as $session) {
            self::assertSame($expected, self::kindsOf(ActiveSessionProofs::query('api', $session, null, null, 50)));
            self::assertSame(array_slice($expected, 0, 2), self::kindsOf(ActiveSessionProofs::query('api', $session, null, null, 2)));
            $further = ActiveSessionProofs::query('api', $session, $this->now->addMinute(), [ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE], 50);

            self::assertSame([ProofKind::RECOVERY_CODE, ProofKind::ADDITIONAL_FACTOR], self::kindsOf($further));
            self::assertSame([], ActiveSessionProofs::query('api', $session, null, [], 50));
            self::assertSame([], ActiveSessionProofs::query('api', $session, $this->now->addMinutes(5), null, 50));

            $first = ActiveSessionProofs::firstFactor('api', $session);

            self::assertNotNull($first);
            self::assertSame([ProofKind::FIRST_FACTOR, 'password', $this->now->getTimestamp()], [$first->kind, $first->method, $first->authenticatedAt->getTimestamp()]);
        }
    }

    /**
     * Proofs of one second come newest id first, as a pending session's do.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testProofsOfOneSecondComeNewestIdFirst(): void
    {
        $record = $this->signedIn()->record;

        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinute(), ['otp'], new Evaluation(true, true));
        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinute(), ['otp'], new Evaluation(true, true));

        $ids    = array_map(static fn (RecordedProof $proof): string => $proof->id, ActiveSessionProofs::query('api', $record->getKey(), $this->now->addMinute(), null, 50));
        $sorted = $ids;

        rsort($sorted);

        self::assertCount(2, $ids);
        self::assertSame($sorted, $ids);
    }

    /**
     * A limit of 1 and of 200 are taken; 0 and 201 are refused before any
     * statement is sent, whatever the session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheLimitIsCheckedBeforeAnythingIsRead(): void
    {
        $key = $this->signedIn()->record->getKey();

        self::assertCount(1, ActiveSessionProofs::query('api', $key, null, null, 1));
        self::assertCount(1, ActiveSessionProofs::query('api', $key, null, null, 200));

        foreach ([0, 201] as $limit) {
            $refused = null;

            self::assertSame([], self::statementsDuring(static function () use ($key, $limit, &$refused): void {
                try {
                    ActiveSessionProofs::query('api', $key, null, null, $limit);
                } catch (\InvalidArgumentException $exception) {
                    $refused = $exception->getMessage();
                }
            }));
            self::assertSame('A session returns between 1 and 200 proofs at a time.', $refused);
        }
    }

    /**
     * An identifier that cannot be a session's key answers nothing with no
     * query; an unknown key, and a session of another guard, a revoked, a
     * pending, an idle or absolutely ended one at the second its deadline
     * names, and a machine's, answer nothing alike, by key and by the instance
     * as stored now (still that session, so only its state refuses it), each
     * with one read of the session and none of its proofs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionItMayNotAnswerForAnswersNothing(): void
    {
        $record = $this->signedIn()->record;
        $admin  = $this->signedIn('admin')->record;
        $key    = $record->getKey();

        self::assertSame([[], null, 0], self::answersFor('api', 'not-a-key'));
        self::assertSame([[], null, 1], self::answersFor('api', (string) Str::uuid7()));
        self::assertSame([[], null, 1], self::answersFor('api', $admin->getKey()));
        self::assertSame([[], null, 1], self::answersFor('api', $admin));

        $states = [
            ['revoked_at' => $this->now, 'revoked_reason' => 'revoked'],
            ['revoked_at' => null, 'revoked_reason' => null, 'status' => 'pending'],
            ['status' => 'active', 'idle_expires_at' => $this->now],
            ['idle_expires_at' => $this->now->addSecond(), 'absolute_expires_at' => $this->now],
            ['absolute_expires_at' => null, 'authenticatable_type' => MachineClient::class],
        ];

        foreach ($states as $state) {
            DB::table('authentication_sessions')->where('id', $key)->update($state);

            $stored = SessionLookup::find($key);

            self::assertNotNull($stored);
            self::assertSame([[], null, 1], self::answersFor('api', $key));
            self::assertSame([[], null, 1], self::answersFor('api', $stored));
        }

        DB::table('authentication_sessions')->where('id', $key)->update(['authenticatable_type' => $record->getAttribute('authenticatable_type')]);

        self::assertSame([1, true, 2], self::answersFor('api', $key, static fn (array $proofs, ?RecordedProof $first): array => [count($proofs), $first !== null]));
    }

    /**
     * A session that is not an Eloquent session, a plain one, a model that is
     * not one, or one that declares the contract without being a model, names
     * none, and is never looked up, though its key names a live session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionThatIsNotAnEloquentSessionIsNeverLookedUp(): void
    {
        $id = (string) IdentifierCoercion::stringify($this->signedIn()->record->getKey());

        self::assertSame([[], null, 0], self::answersFor('api', new PlainSessionFixture($id, $this->now->addHour())));
        self::assertSame([[], null, 0], self::answersFor('api', new StubBareSession(['id' => $id])));
        self::assertSame([[], null, 0], self::answersFor('api', self::nonModelSession($id)));
    }

    /**
     * A key another sign-in of the same owner and guard reused answers, by the
     * key, the new session's own proofs and first factor, never the earlier
     * session's; the earlier session's instance answers nothing, its key no
     * longer holding it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAReusedKeyAnswersItsOwnSessionByKeyAndNothingByTheEarlierInstance(): void
    {
        $earlier = $this->signedIn()->record;
        $key     = $earlier->getKey();

        self::recordProof($earlier, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinute(), ['otp'], new Evaluation(true, true));

        DB::table('authentication_sessions')->where('id', $key)->update(['generation' => (string) Str::uuid7(), 'sign_in_method' => 'passkey']);

        $reused = SessionLookup::find($key);

        self::assertNotNull($reused);

        ProofWriter::clear($reused);
        ProofWriter::record($reused, 'api', UndescribedSignInProof::of('passkey', $this->now->addMinutes(2))->firstFactor());

        $proofs = ActiveSessionProofs::query('api', $key, null, null, 50);

        self::assertSame([ProofKind::FIRST_FACTOR], self::kindsOf($proofs));
        self::assertSame('passkey', $proofs[0]->method);
        self::assertSame('passkey', ActiveSessionProofs::firstFactor('api', $key)?->method);
        self::assertSame([[], null, 1], self::answersFor('api', $earlier));
        self::assertSame('passkey', ActiveSessionProofs::firstFactor('api', $reused)?->method);
    }

    /**
     * Proofs under the session's key bound to another guard or another owner
     * never count for it, and a first factor that no longer counts is none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testProofsBoundElsewhereUnderTheKeyNeverCount(): void
    {
        $record = $this->signedIn()->record;
        $key    = $record->getKey();

        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->addMinute(), ['otp'], new Evaluation(true, true));
        self::recordProof($record, ProofKind::RECOVERY_CODE, $this->now->addMinutes(2), [], new Evaluation(true, false));

        DB::table('authentication_proofs')->where('kind', ProofKind::ADDITIONAL_FACTOR->value)->update(['guard' => 'admin']);
        DB::table('authentication_proofs')->where('kind', ProofKind::RECOVERY_CODE->value)->update(['authenticatable_id' => '999999']);

        self::assertSame([ProofKind::FIRST_FACTOR], self::kindsOf(ActiveSessionProofs::query('api', $key, null, null, 50)));

        DB::table('authentication_proofs')->where('kind', ProofKind::FIRST_FACTOR->value)->update(['voided_at' => $this->now]);

        self::assertSame([], ActiveSessionProofs::query('api', $key, null, null, 50));
        self::assertNull(ActiveSessionProofs::firstFactor('api', $key));
    }

    /**
     * Inside a transaction on the session model's connection the session's row
     * is read locked for update, before its proofs, which are read current (a
     * shared lock where the engine takes one); outside one, both are read
     * plainly; and a session it may not answer for inside one sends no read of
     * its proofs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheRowIsLockedAndTheProofsReadCurrentOnlyInsideATransaction(): void
    {
        $record = $this->signedIn()->record;
        $key    = $record->getKey();

        self::markSharedLocks();

        foreach ([$key, $record] as $session) {
            $reads = [
                static fn (): array => ActiveSessionProofs::query('api', $session, null, null, 50),
                static fn (): ?RecordedProof => ActiveSessionProofs::firstFactor('api', $session),
            ];

            foreach ($reads as $read) {
                self::assertSame([[true, false], [false, self::takesSharedLocks()]], self::locksOf(static fn (): mixed => DB::transaction($read)));
                self::assertSame([[false, false], [false, false]], self::locksOf($read));
            }
        }

        DB::table('authentication_sessions')->where('id', $key)->update(['revoked_at' => $this->now, 'revoked_reason' => 'revoked']);

        self::assertSame([[true, false]], self::locksOf(static fn (): mixed => DB::transaction(static fn (): array => ActiveSessionProofs::query('api', $key, null, null, 50))));
        self::assertSame([[true, false]], self::locksOf(static fn (): mixed => DB::transaction(static fn (): ?RecordedProof => ActiveSessionProofs::firstFactor('api', $key))));
    }

    /**
     * An active session a provider established answers the provenance it
     * records, by its key and by its instance alike, with one read of the
     * session and one of its provenance; a session no provider established
     * answers nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActiveSessionsProvenanceIsRead(): void
    {
        $record = $this->signedIn()->record;
        $plain  = $this->signedIn()->record;
        $key    = $record->getKey();

        ProofWriter::provenance($record, new Provenance('conn-a', 'tenant-1', policyVersion: 'v1', linkId: 'link-a'));

        foreach ([$key, $record] as $session) {
            $provenance = null;

            $statements = self::statementsDuring(static function () use ($session, &$provenance): void {
                $provenance = ActiveSessionProofs::provenance('api', $session);
            });

            self::assertInstanceOf(Provenance::class, $provenance);
            self::assertSame(['conn-a', 'tenant-1', 'v1', 'link-a'], [$provenance->connectionId, $provenance->tenantId, $provenance->policyVersion, $provenance->linkId]);
            self::assertCount(2, $statements);
        }

        self::assertNull(ActiveSessionProofs::provenance('api', $plain->getKey()));
        self::assertNull(ActiveSessionProofs::provenance('api', $plain));
    }

    /**
     * A session it may not answer for answers no provenance, with no read of
     * it: an identifier that cannot be a key, an unknown key, a session of
     * another guard, a revoked, pending, idle or absolutely ended one, a
     * machine's, one given as an instance whose key another owner now holds,
     * and one that is not an Eloquent session.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionItMayNotAnswerForHasNoProvenance(): void
    {
        $record = $this->signedIn()->record;
        $admin  = $this->signedIn('admin')->record;
        $key    = $record->getKey();

        ProofWriter::provenance($record, new Provenance('conn-a'));
        ProofWriter::provenance($admin, new Provenance('conn-b'));

        $provenanceReads = static function (mixed $session): array {
            $found = null;

            $statements = self::statementsDuring(static function () use ($session, &$found): void {
                $found = ActiveSessionProofs::provenance('api', $session);
            });

            return [$found, count(array_filter($statements, static fn (string $sql): bool => str_contains($sql, 'authentication_provenance')))];
        };

        self::assertSame([null, 0], $provenanceReads('not-a-key'));
        self::assertSame([null, 0], $provenanceReads((string) Str::uuid7()));
        self::assertSame([null, 0], $provenanceReads($admin->getKey()));
        self::assertSame([null, 0], $provenanceReads($admin));
        self::assertSame([null, 0], $provenanceReads(new PlainSessionFixture((string) IdentifierCoercion::stringify($key), $this->now->addHour())));
        self::assertSame([null, 0], $provenanceReads(self::nonModelSession((string) IdentifierCoercion::stringify($key))));

        $states = [
            ['revoked_at' => $this->now, 'revoked_reason' => 'revoked'],
            ['revoked_at' => null, 'revoked_reason' => null, 'status' => 'pending'],
            ['status' => 'active', 'idle_expires_at' => $this->now],
            ['idle_expires_at' => $this->now->addSecond(), 'absolute_expires_at' => $this->now],
            ['absolute_expires_at' => null, 'authenticatable_type' => MachineClient::class],
        ];

        foreach ($states as $state) {
            DB::table('authentication_sessions')->where('id', $key)->update($state);

            $stored = SessionLookup::find($key);

            self::assertNotNull($stored);
            self::assertSame([null, 0], $provenanceReads($key));
            self::assertSame([null, 0], $provenanceReads($stored));
        }

        DB::table('authentication_sessions')->where('id', $key)->update(['authenticatable_type' => $record->getAttribute('authenticatable_type')]);

        self::assertSame('conn-a', ActiveSessionProofs::provenance('api', $key)?->connectionId);

        DB::table('authentication_sessions')->where('id', $key)->update(['authenticatable_id' => '999999']);

        self::assertSame([null, 0], $provenanceReads($record));
    }

    /**
     * Inside a transaction on the session model's connection the session's row
     * is locked for update before its provenance, which is read current (a
     * shared lock where the engine takes one); outside one, both are read
     * plainly; and a session it may not answer for sends no read of its
     * provenance.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheProvenanceIsReadLockedOnlyInsideATransaction(): void
    {
        $record = $this->signedIn()->record;
        $key    = $record->getKey();

        ProofWriter::provenance($record, new Provenance('conn-a'));
        self::markSharedLocks();

        $read = static fn (): ?Provenance => ActiveSessionProofs::provenance('api', $key);

        self::assertSame([[true, false], [false, self::takesSharedLocks()]], self::locksOf(static fn (): mixed => DB::transaction($read)));
        self::assertSame([[false, false], [false, false]], self::locksOf($read));

        DB::table('authentication_sessions')->where('id', $key)->update(['revoked_at' => $this->now, 'revoked_reason' => 'revoked']);

        self::assertSame([[true, false]], self::locksOf(static fn (): mixed => DB::transaction($read)));
    }

    /**
     * A transaction open only on another connection holds nothing of the
     * session's, so the reads lock nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATransactionOnAnotherConnectionLocksNothing(): void
    {
        $key = $this->signedIn()->record->getKey();

        self::markSharedLocks();

        $other = DB::connection(self::OTHER);

        $other->beginTransaction();

        try {
            self::assertSame([[false, false], [false, false]], self::locksOf(static fn (): array => ActiveSessionProofs::query('api', $key, null, null, 50)));
            self::assertSame([[false, false], [false, false]], self::locksOf(static fn (): ?RecordedProof => ActiveSessionProofs::firstFactor('api', $key)));
        } finally {
            $other->rollBack();
        }
    }

    /**
     * The reads are a utility: they cannot be instantiated from outside.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(ActiveSessionProofs::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(ActiveSessionProofs::class, $instance);
    }

    /**
     * Register the guards and a second connection to the test database.
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

        $config->set('database.connections.' . self::OTHER, $config->array('database.connections.' . $config->string('database.default')));
    }

    /**
     * A session the seeded identity signed in to on the guard with its password
     * now.
     *
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(string $guard = 'api'): SignedInSession
    {
        if (DB::table('integration_identities')->doesntExist()) {
            $this->seedIdentity();
        }

        $session = $this->sessions($guard)->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * A session of the `api` guard under the key given that declares the
     * Eloquent session contract without being an Eloquent model.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Authentication\Contracts\EloquentSession
     */
    private static function nonModelSession(string $id): EloquentSession
    {
        $session = \Mockery::mock(StubNonModelSession::class);

        $session->shouldReceive('getGuard')->andReturn('api');
        $session->shouldReceive('getSessionIdentifier')->andReturn($id);

        return $session;
    }

    /**
     * What the guard reads of the session, the proofs and the first factor,
     * shaped by the callback when one is given, and how many statements each
     * read sent, the same for both.
     *
     * @param  string  $guard
     * @param  mixed  $session
     * @param  ?\Closure(list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>, ?\SineMacula\Laravel\Authentication\Proofs\RecordedProof): list<mixed>  $shape
     * @return list<mixed>
     *
     * @throws \Throwable
     */
    private static function answersFor(string $guard, mixed $session, ?\Closure $shape = null): array
    {
        $proofs = [];
        $first  = null;

        $queried = self::statementsDuring(static function () use ($guard, $session, &$proofs): void {
            $proofs = ActiveSessionProofs::query($guard, $session, null, null, 50);
        });

        $firstRead = self::statementsDuring(static function () use ($guard, $session, &$first): void {
            $first = ActiveSessionProofs::firstFactor($guard, $session);
        });

        self::assertCount(count($queried), $firstRead);

        return [...($shape === null ? [$proofs, $first] : $shape($proofs, $first)), count($queried)];
    }

    /**
     * For each statement the callback sent, whether it locked for update and
     * whether it took a shared lock, in order.
     *
     * @param  \Closure(): mixed  $callback
     * @return list<array{0: bool, 1: bool}>
     */
    private static function locksOf(\Closure $callback): array
    {
        return array_map(static fn (string $sql): array => [self::locksForUpdate($sql), self::sharesLock($sql)], self::statementsDuring($callback));
    }

    /**
     * The kinds of the proofs, in order.
     *
     * @param  list<\SineMacula\Laravel\Authentication\Proofs\RecordedProof>  $proofs
     * @return list<\SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind>
     */
    private static function kindsOf(array $proofs): array
    {
        return array_map(static fn (RecordedProof $proof): ProofKind => $proof->kind, $proofs);
    }
}
