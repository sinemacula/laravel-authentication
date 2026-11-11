<?php

declare(strict_types = 1);

namespace Tests\Feature\Proofs;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Casts\Json;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\External\ProviderContext;
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
 * Feature tests of the proof writer against a real database.
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

    /** @var string The id a proof judged in memory was given; a UUID, as the key is on PostgreSQL. */
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
     * to the session's key, owner and guard.
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
        self::assertTrue((bool) $row->getAttribute('additional_verification'));
        self::assertNull($row->getAttribute('evidence'));
        self::assertSame('2026-04-06 12:00:00', self::storedInstant($row->getRawOriginal('authenticated_at'))->toDateTimeString());
    }

    /**
     * An external proof whose evidence was accepted is recorded with that
     * evidence, hidden from serialisation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExternalProofIsRecordedWithItsAcceptedEvidence(): void
    {
        $this->seedIdentity();

        $session  = $this->newSession();
        $evidence = new ExternalEvidence(['hwk', 'pin'], 'phrh', CarbonImmutable::now()->subMinute());
        $proof    = new NewProof(
            ProofKind::EXTERNAL_REAUTHENTICATION,
            Purpose::REAUTHENTICATE,
            'external_provider',
            new Channel(ChannelKind::EXTERNAL_PROVIDER, 'conn-a'),
            null,
            new ObservedProperties,
            new Evaluation(true, false, false),
            ['urn:sinemacula:amr:external_provider'],
            CarbonImmutable::now(),
            $evidence,
        );

        ProofWriter::record($session, 'api', $proof, self::JUDGED_PROOF_ID);

        $row = SessionProof::query()->findOrFail(self::JUDGED_PROOF_ID);

        self::assertSame([true, false, false], [$row->accepted, $row->multifactor, $row->additional_verification]);

        $stored = $row->getRawOriginal('evidence');

        self::assertIsString($stored);
        self::assertSame(['methods' => ['hwk', 'pin'], 'context' => 'phrh', 'authenticated_at' => '2026-04-06T11:59:00+00:00'], json_decode($stored, true));
        self::assertArrayNotHasKey('evidence', $row->toArray());
    }

    /**
     * Rows of `[the proof's kind, its evaluation, the additional verification
     * recorded]`.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind, 1: ?\SineMacula\Laravel\Authentication\Proofs\Evaluation, 2: ?bool}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideAdditionalVerifications(): iterable
    {
        yield 'a further factor the adapter says is not one' => [ProofKind::ADDITIONAL_FACTOR, new Evaluation(true, false, false), true];
        yield 'a recovery code the adapter says is one' => [ProofKind::RECOVERY_CODE, new Evaluation(true, false, true), false];
        yield 'an external proof accepted for one' => [ProofKind::EXTERNAL_REAUTHENTICATION, new Evaluation(true, false, true), true];
        yield 'an external proof accepted for a level only' => [ProofKind::EXTERNAL_REAUTHENTICATION, new Evaluation(true, false, false), false];
        yield 'a first factor reauthentication' => [ProofKind::FIRST_FACTOR_REAUTHENTICATION, null, null];
    }

    /**
     * Whether a further factor or a recovery code is recorded as an additional
     * verification follows from its kind.
     *
     * @param  \SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind  $kind
     * @param  ?\SineMacula\Laravel\Authentication\Proofs\Evaluation  $evaluation
     * @param  ?bool  $recorded
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideAdditionalVerifications')]
    public function testAProofIsRecordedAsAnAdditionalVerificationByItsKind(ProofKind $kind, ?Evaluation $evaluation, ?bool $recorded): void
    {
        $this->seedIdentity();

        $channel = new Channel(ChannelKind::AUTHENTICATOR_APP);
        $proof   = new NewProof($kind, Purpose::REAUTHENTICATE, 'totp', $channel, null, new ObservedProperties, $evaluation, ['otp'], CarbonImmutable::now());

        ProofWriter::record($this->newSession(), 'api', $proof, self::JUDGED_PROOF_ID);

        self::assertSame($recorded, SessionProof::query()->findOrFail(self::JUDGED_PROOF_ID)->additional_verification);
    }

    /**
     * Without an id, each proof gets a new time-ordered one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProofWithoutAnIdIsGivenATimeOrderedOne(): void
    {
        $this->seedIdentity();

        $session = $this->newSession();
        $before  = array_map(self::storedString(...), SessionProof::query()->pluck('id')->all());

        ProofWriter::record($session, 'api', self::furtherFactor(CarbonImmutable::now()));
        ProofWriter::record($session, 'api', self::furtherFactor(CarbonImmutable::now()));

        $ids = array_values(array_diff(array_map(self::storedString(...), SessionProof::query()->pluck('id')->all()), $before));

        self::assertCount(2, $ids);

        foreach ($ids as $id) {
            self::assertMatchesRegularExpression('/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', IdentifierCoercion::stringify($id) ?? '');
        }

        self::assertNotSame($ids[0], $ids[1]);
    }

    /**
     * Provenance is recorded under the session's key, with any accepted
     * evidence hidden from serialisation.
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

        $other    = $this->newSession();
        $evidence = new ExternalEvidence(['otp'], null, CarbonImmutable::now());

        ProofWriter::provenance($other, new Provenance('conn-a', evidence: $evidence));

        $accepted = SessionProvenance::query()->findOrFail(IdentifierCoercion::stringify($other->getKey()));

        self::assertSame($evidence->toArray(), $accepted->getAttribute('accepted_evidence'));
        self::assertArrayNotHasKey('accepted_evidence', $accepted->toArray());
        self::assertNull($accepted->getAttribute('provider_context'));
    }

    /**
     * A provenance's provider context is recorded as the package encodes it,
     * whatever JSON encoder Eloquent's casts are given.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheProviderContextIsRecordedAsThePackageEncodesIt(): void
    {
        $this->seedIdentity();

        $session = $this->newSession();
        $context = new ProviderContext(['protocol' => 'saml', 'whole' => 1.0, 'name' => 'Zoë']);

        Json::encodeUsing(static fn (): string => '"replaced"');

        try {
            ProofWriter::provenance($session, new Provenance('conn-a', providerContext: $context));
        } finally {
            Json::encodeUsing(null);
        }

        $row = SessionProvenance::query()->findOrFail(IdentifierCoercion::stringify($session->getKey()));

        self::assertSame($context->toStored(), $row->getAttribute('provider_context'));
        self::assertSame('{"protocol":"saml","whole":1.0,"name":"Zo\u00eb"}', $row->getAttribute('provider_context'));
        self::assertArrayNotHasKey('provider_context', $row->toArray());
        self::assertStringNotContainsString('saml', (string) json_encode($row));
    }

    /**
     * A proof a model event cancels is refused.
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
     * Voiding a factor marks only the session's proofs made with that exact
     * factor, and a proof already voided keeps its time.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testVoidingAFactorMarksOnlyTheSessionsProofsMadeWithIt(): void
    {
        $this->seedIdentity();

        $session = $this->newSession();
        $other   = $this->newSession();
        $now     = CarbonImmutable::now();

        $voided = $this->recorded($session, 'api', 'factor-1');
        $kept   = [
            $this->recorded($session, 'api', 'Factor-1'),
            $this->recorded($session, 'api', 'factor-1 '),
            $this->recorded($session, 'api', 'factor-2'),
            $this->recorded($session, 'admin', 'factor-1'),
            $this->recorded($other, 'api', 'factor-1'),
        ];

        $foreign = $this->recorded($session, 'api', 'factor-1');

        SessionProof::query()->whereKey($foreign)->update(['authenticatable_id' => '999']);

        self::assertSame(1, ProofWriter::void($session, 'api', 'factor-1', $now->addMinute()));
        self::assertSame('2026-04-06 12:01:00', self::storedInstant(SessionProof::query()->findOrFail($voided)->getRawOriginal('voided_at'))->toDateTimeString());
        self::assertSame(0, SessionProof::query()->whereKey([...$kept, $foreign])->whereNotNull('voided_at')->count());

        self::assertSame(0, ProofWriter::void($session, 'api', 'factor-1', $now->addMinutes(2)));
        self::assertSame('2026-04-06 12:01:00', self::storedInstant(SessionProof::query()->findOrFail($voided)->getRawOriginal('voided_at'))->toDateTimeString());
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
        $session = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session?->record;

        self::assertInstanceOf(Session::class, $session);

        return $session;
    }

    /**
     * Record a further factor made now on the session and return its id.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @param  string  $guard
     * @param  string  $factor
     * @return string
     *
     * @throws \Throwable
     */
    private function recorded(Session $session, string $guard, string $factor): string
    {
        $id = Str::uuid7()->toString();

        ProofWriter::record($session, $guard, self::furtherFactor(CarbonImmutable::now(), $factor), $id);

        return $id;
    }

    /**
     * An accepted further factor for sign-in.
     *
     * @param  \Carbon\CarbonImmutable  $at
     * @param  string  $factor
     * @return \SineMacula\Laravel\Authentication\Proofs\NewProof
     */
    private static function furtherFactor(CarbonImmutable $at, string $factor = 'factor-1'): NewProof
    {
        return new NewProof(
            ProofKind::ADDITIONAL_FACTOR,
            Purpose::SIGN_IN,
            'totp',
            new Channel(ChannelKind::AUTHENTICATOR_APP),
            $factor,
            new ObservedProperties,
            new Evaluation(true, true),
            ['otp'],
            $at,
        );
    }
}
