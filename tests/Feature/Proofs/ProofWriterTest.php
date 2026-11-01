<?php

declare(strict_types = 1);

namespace Tests\Feature\Proofs;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Models\SessionProvenance;
use SineMacula\Laravel\Authentication\Proofs\Channel;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\NewProof;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Feature tests of the proof writer against a real database: a proof recorded
 * under the id it was judged by in memory or under a new time-ordered one,
 * bound to the session it is recorded on; provenance; a save a model event
 * cancels; and what an earlier session left under a reused key cleared.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofWriter::class)]
final class ProofWriterTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string The id a proof judged in memory was given: a UUID, as the proofs table's key is on PostgreSQL. */
    private const string JUDGED_PROOF_ID = '0190f1d2-7c4e-7a3b-9f10-2b3c4d5e6f71';

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));
        CarbonImmutable::setTestNow(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

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

        parent::tearDown();
    }

    /**
     * A proof judged in memory is recorded under the id it was judged by, bound
     * to the session's key, owner and the guard given, with its parts and its
     * time to the second.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofIsRecordedUnderTheIdGiven(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->newSession();

        ProofWriter::record($session, 'admin', self::furtherFactor(CarbonImmutable::now()->addMilliseconds(400)), self::JUDGED_PROOF_ID);

        $row = SessionProof::query()->findOrFail(self::JUDGED_PROOF_ID);

        self::assertSame(IdentifierCoercion::stringify($session->getKey()), $row->getAttribute('session_id'));
        self::assertSame('admin', $row->getAttribute('guard'));
        self::assertSame($identity->getMorphClass(), $row->getAttribute('authenticatable_type'));
        self::assertSame(IdentifierCoercion::stringify($identity->getKey()), $row->getAttribute('authenticatable_id'));
        self::assertSame(ProofKind::ADDITIONAL_FACTOR->value, $row->getAttribute('kind'));
        self::assertSame(Purpose::SIGN_IN->value, $row->getAttribute('purpose'));
        self::assertSame(ChannelKind::AUTHENTICATOR_APP->value, $row->getAttribute('channel_kind'));
        self::assertSame('factor-1', $row->getAttribute('factor_reference'));
        self::assertTrue((bool) $row->getAttribute('accepted'));
        self::assertSame('2026-04-06 12:00:00', CarbonImmutable::parse($row->getRawOriginal('authenticated_at'))->toDateTimeString());
    }

    /**
     * Without an id, each proof gets a new time-ordered one, so the session's
     * proofs read back in the order they were recorded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofWithoutAnIdIsGivenATimeOrderedOne(): void
    {
        $this->seedIdentity();

        $session = $this->newSession();
        $before  = SessionProof::query()->pluck('id')->all();

        ProofWriter::record($session, 'api', self::furtherFactor(CarbonImmutable::now()));
        ProofWriter::record($session, 'api', self::furtherFactor(CarbonImmutable::now()));

        $ids = array_values(array_diff(SessionProof::query()->pluck('id')->all(), $before));

        self::assertCount(2, $ids);

        foreach ($ids as $id) {
            self::assertMatchesRegularExpression('/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', IdentifierCoercion::stringify($id) ?? '');
        }

        self::assertNotSame($ids[0], $ids[1]);
    }

    /**
     * Provenance is recorded under the session's key, with no evidence.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testProvenanceIsRecordedUnderTheSessionsKey(): void
    {
        $this->seedIdentity();

        $session = $this->newSession();

        ProofWriter::provenance($session, new Provenance('conn-a', 'tenant-1', policyVersion: 'v1'));

        $row = SessionProvenance::query()->findOrFail(IdentifierCoercion::stringify($session->getKey()));

        self::assertSame('conn-a', $row->getAttribute('connection_id'));
        self::assertSame('tenant-1', $row->getAttribute('tenant_id'));
        self::assertSame('v1', $row->getAttribute('policy_version'));
        self::assertNull($row->getAttribute('accepted_evidence'));
    }

    /**
     * A proof a model event cancels is refused loudly, so the session written
     * with it rolls back rather than standing without it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofAModelEventCancelsIsRefused(): void
    {
        $this->seedIdentity();

        $session = $this->newSession();

        Event::listen('eloquent.creating: ' . SessionProof::class, static fn (): bool => false);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(SessionProof::class . ' was not saved');

        ProofWriter::record($session, 'api', self::furtherFactor(CarbonImmutable::now()));
    }

    /**
     * Clearing a key removes every proof and the provenance recorded under it,
     * and leaves another session's alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testClearingAKeyRemovesWhatWasRecordedUnderIt(): void
    {
        $this->seedIdentity();

        $session = $this->newSession();
        $other   = $this->newSession();

        ProofWriter::record($session, 'api', self::furtherFactor(CarbonImmutable::now()));
        ProofWriter::provenance($session, new Provenance('conn-a'));

        $kept = SessionProof::query()->where('session_id', IdentifierCoercion::stringify($other->getKey()))->count();

        ProofWriter::clear($session);

        self::assertSame(0, SessionProof::query()->where('session_id', IdentifierCoercion::stringify($session->getKey()))->count());
        self::assertNull(SessionProvenance::query()->find(IdentifierCoercion::stringify($session->getKey())));
        self::assertSame($kept, SessionProof::query()->where('session_id', IdentifierCoercion::stringify($other->getKey()))->count());

        ProofWriter::clear($session);

        self::assertSame(0, SessionProof::query()->where('session_id', IdentifierCoercion::stringify($session->getKey()))->count());
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
     * A session of the seeded identity, signed in with its password.
     *
     * @return \SineMacula\Laravel\Authentication\Models\Session
     *
     * @throws \Throwable
     */
    private function newSession(): Session
    {
        $session = $this->sessions()->signIn('password', self::credentials())->session?->record;

        self::assertInstanceOf(Session::class, $session);

        return $session;
    }

    /**
     * An accepted further factor for sign-in, made at the time given.
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @return \SineMacula\Laravel\Authentication\Proofs\NewProof
     */
    private static function furtherFactor(CarbonImmutable $at): NewProof
    {
        return new NewProof(
            ProofKind::ADDITIONAL_FACTOR,
            Purpose::SIGN_IN,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP),
            'factor-1',
            new ObservedProperties,
            new Evaluation(true, true),
            ['otp'],
            $at,
        );
    }
}
