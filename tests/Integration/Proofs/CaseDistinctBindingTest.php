<?php

declare(strict_types = 1);

namespace Tests\Integration\Proofs;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
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
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Integration tests, against each supported database, of proofs whose session
 * keys or `amr` values differ only in case: MySQL's default collations count
 * such values as equal, and the proofs' columns must not. A session counts and
 * clears only the proofs and provenance recorded under its own key, byte for
 * byte, and the claims keep two values that differ only in case apart.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionProofs::class)]
#[CoversClass(ProofWriter::class)]
#[CoversClass(AuthenticationClaims::class)]
final class CaseDistinctBindingTest extends TestCase
{
    use InteractsWithProofs, InteractsWithSessions;

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
     * A session of the same owner and guard whose key is this session's in
     * upper case (a custom session model's key, on a table that keeps case)
     * keeps its own step-up and provenance: neither counts for this session,
     * both are recorded beside this session's own, and clearing that key leaves
     * this session's first factor and provenance where they were.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionWhoseKeyDiffersOnlyInCaseSharesNothing(): void
    {
        $identity = $this->seedIdentity();
        $record   = $this->sessions()->start($identity, null, 'sso', null, new Provenance('connection-7'))->session?->record;

        self::assertInstanceOf(Session::class, $record);

        $key  = (string) IdentifierCoercion::stringify($record->getKey());
        $twin = (new Session)->forceFill([...$record->getAttributes(), 'id' => strtoupper($key)]);

        self::assertNotSame($key, $twin->getKey());

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
     * Two further factors whose `amr` values differ only in case each keep
     * their value in the claims, in the order they were made.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testValuesThatDifferOnlyInCaseStayApart(): void
    {
        $this->seedIdentity();

        $record = $this->sessions()->signIn('password', self::credentials())->session?->record;

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
}
