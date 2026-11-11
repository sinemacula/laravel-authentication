<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\ExternalEvidencePolicy;
use SineMacula\Laravel\Authentication\External\ExternalEvidence;
use SineMacula\Laravel\Authentication\External\ExternalResult;
use SineMacula\Laravel\Authentication\Models\Session;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Requirements\Enums\RequirementKind;
use SineMacula\Laravel\Authentication\Sessions\ConnectionRevocations;
use SineMacula\Laravel\Authentication\Sessions\ExternalReauthentication;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\External\ScriptedEvidencePolicy;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Integration tests that external sessions are read on the primary while the
 * replica lags.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionProofs::class)]
#[CoversClass(ExternalReauthentication::class)]
#[CoversClass(ConnectionRevocations::class)]
final class ReplicaExternalSessionsTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithLaggingReplica, InteractsWithSessions;

    /** @var \Tests\Integration\Fixtures\IntegrationIdentity The identity both the primary and the replica hold. */
    private IntegrationIdentity $identity;

    /**
     * Create the identity table on the primary and the replica and seed an
     * identity both hold.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createOnPrimaryAndReplica('integration_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $this->identity = $this->seedIdentity();

        $this->copyRowToReplica('integration_identities', $this->identity->getKey());
    }

    /**
     * Release the clock and remove the temporary database files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();

        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * A session only the primary holds reauthenticates through the link and
     * stands for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASessionOnlyThePrimaryHoldsReauthenticatesAndStands(): void
    {
        $now = CarbonImmutable::now()->startOfSecond();

        CarbonImmutable::setTestNow($now);

        $record = $this->signedIn();

        $this->assertTheReplicaHoldsNoSession();

        $result = new ExternalResult('connection-7', self::ISSUER, 'subject-1', authenticatedAt: $now);

        self::assertNull($this->sessions()->externalStanding($record->getKey(), $this->identity, 'connection-7'));
        self::assertNull(DB::transaction(fn (): mixed => $this->sessions()->externalStanding($record->getKey(), $this->identity, 'connection-7', 'link-1')));
        self::assertTrue($this->sessions()->reauthenticateExternally($record->getKey(), $result, self::requestClient())->isIssued());
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('authentication_proofs')->count());
    }

    /**
     * Evidence only the primary holds is read as the session's accepted
     * evidence.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testEvidenceOnlyThePrimaryHoldsIsRead(): void
    {
        app()->instance(ExternalEvidencePolicy::class, new ScriptedEvidencePolicy([RequirementKind::MULTIFACTOR]));

        $evidence = new ExternalEvidence(['mfa'], null, CarbonImmutable::now()->startOfSecond());
        $record   = $this->signedIn($evidence);

        $this->assertTheReplicaHoldsNoSession();

        self::assertEquals([$evidence], SessionProofs::acceptedEvidence($record));
        self::assertEquals($evidence, SessionProofs::provenance($record)?->evidence);
    }

    /**
     * A link's removal or widened scope ends a session only the primary holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinksRevocationEndsASessionOnlyThePrimaryHolds(): void
    {
        $removed = $this->signedIn();
        $widened = $this->signedIn(linkId: 'link-2', subject: 'subject-2');

        $this->assertTheReplicaHoldsNoSession();

        self::assertSame(1, $this->sessions()->linkRemoved($this->identity, 'connection-7', 'link-1'));
        self::assertSame(1, $this->sessions()->linkScopeWidened($this->identity, 'connection-7', 'link-2'));
        $reason = static fn (Session $session): mixed => Session::query()->whereKey($session->getKey())->useWritePdo()->value('revoked_reason');

        self::assertSame(['link_removed', 'link_scope_widened'], [$reason($removed), $reason($widened)]);
    }

    /**
     * Configure the guards over a lagging read/write split.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        $config = app(ConfigRepository::class);

        self::configureSessionGuards($config);

        $this->configureLaggingReplica($config);
    }

    /**
     * Create the package tables on the primary and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica();
    }

    /**
     * Sign the seeded identity in through the link with the evidence and return
     * the session record.
     *
     * @param  ?\SineMacula\Laravel\Authentication\External\ExternalEvidence  $evidence
     * @param  string  $linkId
     * @param  string  $subject
     * @return \SineMacula\Laravel\Authentication\Models\Session
     *
     * @throws \Throwable
     */
    private function signedIn(?ExternalEvidence $evidence = null, string $linkId = 'link-1', string $subject = 'subject-1'): Session
    {
        $record = $this->sessions()->signInExternally(
            $this->linkedResult($this->identity, linkId: $linkId, subject: $subject, evidence: $evidence),
            self::requestContext(),
        )->session?->record;

        self::assertInstanceOf(Session::class, $record);

        return $record;
    }

    /**
     * Assert the replica has seen no session, proof or provenance.
     *
     * @return void
     */
    private function assertTheReplicaHoldsNoSession(): void
    {
        foreach (['authentication_sessions', 'authentication_proofs', 'authentication_provenance'] as $table) {
            self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table($table)->count(), $table);
        }
    }
}
