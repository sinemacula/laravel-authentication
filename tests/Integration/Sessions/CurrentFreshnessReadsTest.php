<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Freshness\ConfiguredFreshness;
use SineMacula\Laravel\Authentication\IdentifierChanges\Enums\IdentifierChangeRequestStatus;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Passwords\PasswordChanges;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofBinding;
use SineMacula\Laravel\Authentication\Proofs\ProofResult;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\SessionRecords\IssuanceGuard;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use SineMacula\Laravel\Authentication\Sessions\RecentAuthentication;
use Tests\Concerns\ChangesIdentifiers;
use Tests\Concerns\InteractsWithIsolationLevels;
use Tests\Integration\Fixtures\ChangeableIdentity;
use Tests\TestCase;

/**
 * The freshness judgements the package makes under the identity's and the
 * session's locks, an identifier change request's and a password
 * establishment's, on PostgreSQL and MySQL, on two connections to one database,
 * inside a caller's transaction at READ COMMITTED and at REPEATABLE READ that
 * made a plain read first: meanwhile the other connection commits a change to
 * the session's proofs as the package writes it (a step-up, or a step-up voided
 * as a factor's removal voids it, after the session's issuance guard); then the
 * caller's transaction makes the request or the establishment. Freshness for
 * both takes a step-up here, so the step-up is the proof that decides.
 *
 * At READ COMMITTED, and on MySQL at REPEATABLE READ (whose plain reads return
 * the snapshot of the transaction's first read, so only the judgement's locking
 * reads see the change), the judgement is made on the change committed: a
 * voided step-up never counts, so the request or establishment is refused, and
 * a step-up committed meanwhile counts. On PostgreSQL's REPEATABLE READ the
 * session's lock fails to serialise instead, and once the caller retries the
 * whole transaction the judgement is made on the change. A judgement that read
 * the snapshot would send the request or set the password on a step-up that no
 * longer counts, or refuse the establishment for want of one that does.
 *
 * Skipped on SQLite, whose in-memory database each connection would have to
 * itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RecentAuthentication::class)]
#[CoversClass(PasswordChanges::class)]
#[CoversClass(ConfiguredFreshness::class)]
final class CurrentFreshnessReadsTest extends TestCase
{
    use ChangesIdentifiers, InteractsWithIsolationLevels;

    /** @var string The second connection to the test database, the one that commits the change. */
    private const string OTHER = 'other';

    /** @var string The password an establishment sets. */
    private const string NEW_PASSWORD = 'a brand new long passphrase';

    /**
     * Skip where two connections cannot share the database, add the second
     * connection, start from a known moment with the fakes bound, and have an
     * identifier change and a password establishment take a step-up.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        if (DB::connection()->getDriverName() === 'sqlite') {
            self::markTestSkipped('Two connections need a shared database server.');
        }

        $config = app(ConfigRepository::class);

        $config->set('database.connections.' . self::OTHER, $config->get('database.connections.' . $config->string('database.default')));

        $this->startChanging();

        foreach (['identifier_change', 'password_establishment'] as $operation) {
            $config->set('authentication.freshness.' . $operation, ['max_age_seconds' => 900, 'proofs' => ['additional_factor']]);
        }

        self::limitLockWaits('testing');
        self::limitLockWaits(self::OTHER);
    }

    /**
     * Close the second connection, drop the table and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        DB::disconnect(self::OTHER);

        if (isset($this->now)) {
            $this->stopChanging();
        }

        parent::tearDown();
    }

    /**
     * An identifier change request proven by a session never counts the
     * session's step-up voided after the caller's first read: the check before
     * the change's transaction may still find it in the snapshot, but the check
     * under the identity's and the session's locks does not, so the request is
     * refused (`reauthentication_required`) with nothing written or sent.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAnIdentifierChangeRequestNeverCountsAStepUpVoidedMeanwhile(string $level): void
    {
        $identity = self::seedChangeable();
        $session  = $this->steppedUp($identity);

        $status = $this->judgeAfter(
            $level,
            fn () => $this->voidElsewhere($session),
            fn (): IdentifierChangeRequestStatus => $this->changes()->requestByCode(
                $identity,
                'email',
                self::NEW_EMAIL,
                Reauthentication::session($session),
                self::requestClient(),
            )->status,
        );

        self::assertSame(IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED, $status);
        self::assertSame([0, 0], [self::rows('identifier_changes'), $this->sender->count()]);
    }

    /**
     * An identifier change request proven by a session is checked first before
     * the change's transaction, with a plain read, which at REPEATABLE READ
     * returns the caller's snapshot (on MySQL and on PostgreSQL alike): a
     * step-up committed after the caller's first read is missed there and the
     * request refused (`reauthentication_required`, failing closed), before
     * anything is locked. At READ COMMITTED the check, and the one under the
     * locks, count it, and the request is sent.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAnIdentifierChangeRequestCountsAStepUpCommittedMeanwhileOnlyAtReadCommitted(string $level): void
    {
        $identity = self::seedChangeable();
        $session  = self::started($identity);

        self::beginTransactionAt($level);

        self::assertGreaterThan(0, DB::table('authentication_proofs')->count());

        $this->stepUpElsewhere($identity, $session);

        $status = $this->changes()->requestByCode($identity, 'email', self::NEW_EMAIL, Reauthentication::session($session), self::requestClient())->status;

        DB::commit();

        $missed = $level === 'repeatable read';

        self::assertSame($missed ? IdentifierChangeRequestStatus::REAUTHENTICATION_REQUIRED : IdentifierChangeRequestStatus::SENT, $status);
        self::assertSame($missed ? 0 : 1, self::rows('identifier_changes'));
    }

    /**
     * A password establishment never counts the session's step-up voided after
     * the caller's first read: it is refused (`reauthentication_required`), and
     * the identity still has no password and its other sessions are kept.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAnEstablishmentNeverCountsAStepUpVoidedMeanwhile(string $level): void
    {
        $identity = self::seedPasswordless();
        $session  = $this->steppedUp($identity);
        $other    = self::started($identity);

        $outcome = $this->judgeAfter(
            $level,
            fn () => $this->voidElsewhere($session),
            static fn (): ?string => Auth::passwords('web')->establish($session, self::NEW_PASSWORD, self::requestClient())->reason?->value,
        );

        self::assertSame('reauthentication_required', $outcome);
        self::assertNull(DB::table('changeable_identities')->value('password'));
        self::assertNull(DB::table('authentication_sessions')->where('id', $other->getKey())->value('revoked_at'));
    }

    /**
     * A password establishment counts a step-up committed after the caller's
     * first read: the password is set, and the identity's other session ends.
     *
     * @param  string  $level
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideIsolationLevels')]
    public function testAnEstablishmentCountsAStepUpCommittedMeanwhile(string $level): void
    {
        $identity = self::seedPasswordless();
        $session  = self::started($identity);
        $other    = self::started($identity);

        $set = $this->judgeAfter(
            $level,
            fn () => $this->stepUpElsewhere($identity, $session),
            static fn (): bool => Auth::passwords('web')->establish($session, self::NEW_PASSWORD, self::requestClient())->isSet(),
        );

        self::assertTrue($set);
        self::assertNotNull(DB::table('changeable_identities')->value('password'));
        self::assertSame('password_established', DB::table('authentication_sessions')->where('id', $other->getKey())->value('revoked_reason'));
    }

    /**
     * Register the guards the tests change identifiers and set passwords
     * through.
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

        self::configureChangeGuards($app->make(ConfigRepository::class));
    }

    /**
     * Open the caller's transaction at the isolation level and read plainly
     * (the snapshot), have the other connection commit the change, then run the
     * call in the caller's transaction and commit it, returning what it
     * answered. Where the transaction reads a snapshot every read keeps
     * (PostgreSQL's REPEATABLE READ), the call fails to serialise first, and
     * the caller retries the whole transaction.
     *
     * @template TJudged
     *
     * @param  string  $level
     * @param  \Closure(): void  $change
     * @param  \Closure(): TJudged  $judge
     * @return TJudged
     *
     * @throws \Throwable
     */
    private function judgeAfter(string $level, \Closure $change, \Closure $judge): mixed
    {
        self::beginTransactionAt($level);

        self::assertGreaterThan(0, DB::table('authentication_proofs')->count());

        $change();

        if (self::readsASnapshot($level)) {
            self::assertSame('40001', self::serializationFailure($judge));

            self::beginTransactionAt($level);
        }

        $judged = $judge();

        DB::commit();

        return $judged;
    }

    /**
     * Run the work on the other connection, as the default one, in a
     * transaction of its own that commits before this returns.
     *
     * @param  \Closure(): void  $work
     * @return void
     *
     * @throws \Throwable
     */
    private function elsewhere(\Closure $work): void
    {
        $manager = app(DatabaseManager::class);
        $default = $manager->getDefaultConnection();

        $manager->setDefaultConnection(self::OTHER);

        try {
            DB::transaction($work);
        } finally {
            $manager->setDefaultConnection($default);
        }
    }

    /**
     * Step the session up with `factor-1` on the other connection.
     *
     * @param  \Tests\Integration\Fixtures\ChangeableIdentity  $identity
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @return void
     *
     * @throws \Throwable
     */
    private function stepUpElsewhere(ChangeableIdentity $identity, Session $session): void
    {
        $this->elsewhere(fn () => self::assertTrue(Auth::sessions('web')->stepUp($this->stepUp($identity, $session), self::requestClient())->isIssued()));
    }

    /**
     * Void the session's proofs made with `factor-1` on the other connection,
     * after its issuance guard, as a factor's removal voids them.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @return void
     *
     * @throws \Throwable
     */
    private function voidElsewhere(Session $session): void
    {
        $this->elsewhere(function () use ($session): void {
            $row = SessionLookup::lock($session->getKey());

            self::assertNotNull($row);

            IssuanceGuard::hold($row);

            self::assertSame(1, ProofWriter::void($row, 'web', 'factor-1', $this->now));
        });
    }

    /**
     * A session of the identity on the `web` guard, started just now and
     * stepped up with `factor-1`.
     *
     * @param  \Tests\Integration\Fixtures\ChangeableIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Models\Session
     *
     * @throws \Throwable
     */
    private function steppedUp(ChangeableIdentity $identity): Session
    {
        $session = self::started($identity);

        self::assertTrue(Auth::sessions('web')->stepUp($this->stepUp($identity, $session), self::requestClient())->isIssued());

        return $session;
    }

    /**
     * An accepted further factor's step-up of the session, made now with
     * `factor-1`.
     *
     * @param  \Tests\Integration\Fixtures\ChangeableIdentity  $identity
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @return \SineMacula\Laravel\Authentication\Proofs\ProofResult
     */
    private function stepUp(ChangeableIdentity $identity, Session $session): ProofResult
    {
        return new ProofResult(
            ProofKind::ADDITIONAL_FACTOR,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP),
            'factor-1',
            new ObservedProperties,
            new Evaluation(true, true),
            ['otp'],
            $this->now,
            new ProofBinding($identity, 'web', $session->getKey(), Purpose::STEP_UP),
        );
    }

    /**
     * Persist an identity as `seedChangeable()` does, but with no password.
     *
     * @return \Tests\Integration\Fixtures\ChangeableIdentity
     */
    private static function seedPasswordless(): ChangeableIdentity
    {
        $identity = self::seedChangeable();

        $identity->forceFill(['password' => null])->save();

        return $identity;
    }

    /**
     * A session of the identity on the `web` guard, started just now.
     *
     * @param  \Tests\Integration\Fixtures\ChangeableIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Models\Session
     *
     * @throws \Throwable
     */
    private static function started(ChangeableIdentity $identity): Session
    {
        $record = Auth::sessions('web')->start($identity, null, 'password', self::requestContext())->session?->record;

        self::assertInstanceOf(Session::class, $record);

        return $record;
    }
}
