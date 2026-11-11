<?php

declare(strict_types = 1);

namespace Tests\Integration\Proofs;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Relations\Relation;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Concerns\PrunesSessions;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationClaims;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Evaluation;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Proofs\ProofWriter;
use SineMacula\Laravel\Authentication\Proofs\Provenance;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Proofs\UndescribedFirstFactor;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Integration tests of proofs whose session keys or `amr` values differ only in
 * case or trailing spaces.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionProofs::class)]
#[CoversClass(ProofWriter::class)]
#[CoversClass(AuthenticationClaims::class)]
#[CoversTrait(PrunesSessions::class)]
final class ByteDistinctBindingTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithProofs, InteractsWithSessions;

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
     * Drop the tables and release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * Ways a session key can differ from another only where MySQL's collations
     * do not look.
     *
     * @return iterable<string, array{\Closure(string): string}>
     */
    public static function twinKeys(): iterable
    {
        yield 'in case' => [strtoupper(...)];

        yield 'by a trailing space' => [static fn (string $key): string => $key . ' '];
    }

    /**
     * A session under a twin key shares no step-up, provenance or clearing with
     * this one.
     *
     * @param  \Closure(string): string  $spell
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('twinKeys')]
    public function testASessionUnderATwinKeySharesNothing(\Closure $spell): void
    {
        [$record, $twin] = $this->sessionAndTwin($spell);

        self::recordProof($twin, ProofKind::ADDITIONAL_FACTOR, $this->now, ['otp'], new Evaluation(true, true));

        ProofWriter::provenance($twin, new Provenance('connection-8'));

        self::assertSame([FirstFactor::EXTERNAL_PROVIDER_METHOD], AuthenticationClaims::forSession($record)->methods);
        self::assertNull(SessionProofs::newestMeeting($record, new FreshnessRequirement(900, [ProofKind::ADDITIONAL_FACTOR]), $this->now));

        ProofWriter::clear($twin);

        self::assertSame(['first_factor'], array_map(static fn (SessionProof $proof): string => $proof->kind, self::proofsOf($record)));
        self::assertSame('connection-7', self::provenanceOf($record)?->connection_id);
        self::assertSame([[], null], [self::proofsOf($twin), self::provenanceOf($twin)]);
    }

    /**
     * Pruning a session leaves the proofs and provenance of its twin key.
     *
     * @param  \Closure(string): string  $spell
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('twinKeys')]
    public function testPruningASessionLeavesItsTwinsProofs(\Closure $spell): void
    {
        [$record, $twin] = $this->sessionAndTwin($spell);

        self::recordProof($twin, ProofKind::ADDITIONAL_FACTOR, $this->now, ['otp'], new Evaluation(true, true));

        ProofWriter::provenance($twin, new Provenance('connection-8'));

        Session::query()->whereKey($record->getKey())->update(['revoked_at' => $this->now->subYear()]);

        self::assertSame(1, (new Session)->pruneAll());
        self::assertSame([[], null], [self::proofsOf($record), self::provenanceOf($record)]);
        self::assertSame(['additional_factor'], array_map(static fn (SessionProof $proof): string => $proof->kind, self::proofsOf($twin)));
        self::assertSame('connection-8', self::provenanceOf($twin)?->connection_id);
    }

    /**
     * A key, owner and guard of 255 four-byte characters each are kept whole.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testBindingsOf255FourByteCharactersAreKeptWhole(): void
    {
        $alias  = str_repeat("\u{1D4AF}", 255);
        $record = $this->sessions()->start(UndescribedFirstFactor::of($this->seedIdentity()), null, 'sso', self::requestContext())->session?->record;

        self::assertInstanceOf(Session::class, $record);

        $session = (new Session)->forceFill([
            ...$record->getAttributes(),
            'id'                   => str_repeat("\u{1F511}", 255),
            'authenticatable_type' => $alias,
            'authenticatable_id'   => str_repeat("\u{1F464}", 255),
            'guard'                => str_repeat("\u{1F6E1}", 255),
        ]);

        Relation::morphMap([$alias => IntegrationIdentity::class]);

        try {
            self::recordProof($session, ProofKind::ADDITIONAL_FACTOR, $this->now, ['otp'], new Evaluation(true, true));

            ProofWriter::provenance($session, new Provenance('connection-8'));

            $proof = SessionProofs::newestMeeting($session, new FreshnessRequirement(900, [ProofKind::ADDITIONAL_FACTOR]), $this->now);
        } finally {
            Relation::morphMap([], false);
        }

        self::assertSame([ProofKind::ADDITIONAL_FACTOR, ['otp']], [$proof?->kind, $proof?->methods]);
        self::assertSame('connection-8', self::provenanceOf($session)?->connection_id);
    }

    /**
     * Two `amr` values that differ only in case stay apart in the claims.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testValuesThatDifferOnlyInCaseStayApart(): void
    {
        $this->seedIdentity();

        $record = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session?->record;

        self::assertInstanceOf(Session::class, $record);

        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->addSecond(), ['urn:example:A'], new Evaluation(true, false));
        self::recordProof($record, ProofKind::ADDITIONAL_FACTOR, $this->now->addSeconds(2), ['urn:example:a'], new Evaluation(true, false));

        self::assertSame(['pwd', 'urn:example:A', 'urn:example:a'], AuthenticationClaims::forSession($record)->methods);
    }

    /**
     * Configure the session guards.
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
     * An externally established session with its provenance, and an unsaved
     * twin keyed by the given spelling.
     *
     * @param  \Closure(string): string  $spell
     * @return array{0: \SineMacula\Laravel\Authentication\Models\Session, 1: \SineMacula\Laravel\Authentication\Models\Session}
     *
     * @throws \Throwable
     */
    private function sessionAndTwin(\Closure $spell): array
    {
        $identity = $this->seedIdentity();
        $record   = $this->sessions()->signInExternally($this->linkedResult($identity), self::requestContext())->session?->record;

        self::assertInstanceOf(Session::class, $record);

        $key  = (string) IdentifierCoercion::stringify($record->getKey());
        $twin = (new Session)->forceFill([...$record->getAttributes(), 'id' => $spell($key)]);

        self::assertNotSame($key, $twin->getKey());

        return [$record, $twin];
    }
}
