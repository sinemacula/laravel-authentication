<?php

declare(strict_types = 1);

namespace Tests\Integration\Proofs;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Context\AuthenticationContext;
use SineMacula\Laravel\Authentication\Context\ContributionSubject;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Freshness\ConfiguredFreshness;
use SineMacula\Laravel\Authentication\Freshness\Operations;
use SineMacula\Laravel\Authentication\Jwt\Enums\SubjectType;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationClaims;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\RecordedProof;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Sessions\ActiveSessionProofs;
use SineMacula\Laravel\Authentication\Sessions\SessionStepUp;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Integration tests of a session's proofs over a read/write split whose replica
 * lags: every read of them goes to the primary, so a proof just written counts
 * for the claims, for freshness and for the next step-up straight away, and an
 * active session's proofs, read through the session service or a contribution
 * subject, are its proofs and revocation as the primary holds them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionProofs::class)]
#[CoversClass(AuthenticationClaims::class)]
#[CoversClass(ConfiguredFreshness::class)]
#[CoversClass(SessionStepUp::class)]
#[CoversClass(ActiveSessionProofs::class)]
#[CoversClass(ContributionSubject::class)]
final class ReplicaProofsTest extends TestCase
{
    use InteractsWithLaggingReplica, InteractsWithProofs, InteractsWithSessions;

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

        $this->copyRowToReplica('integration_identities', $this->seedIdentity()->getKey());
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
     * A session and its first factor only the primary holds give claims and
     * freshness straight after the sign-in, and a step-up's proof the replica
     * has not seen counts for the next.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testProofsTheReplicaHasNotSeenCount(): void
    {
        $now = CarbonImmutable::now()->startOfSecond();

        CarbonImmutable::setTestNow($now);

        $session = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('authentication_proofs')->count());
        self::assertSame(['pwd'], AuthenticationClaims::forSession($session->record)->methods);
        self::assertSame(ProofKind::FIRST_FACTOR, app(FreshnessPolicy::class)->freshProof($session->record, Operations::IDENTIFIER_CHANGE)?->kind);

        // A minute on, so the step-up's values follow the first factor's.
        CarbonImmutable::setTestNow($now->addMinute());

        self::assertTrue($this->sessions()->stepUp(self::adapterProof($session->identity, 'api', $session->record->getKey()), self::requestClient())->isIssued());

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('authentication_proofs')->count());
        self::assertSame(['pwd', 'otp', 'mfa'], AuthenticationClaims::forSession($session->record)->methods);
        self::assertSame(ProofKind::ADDITIONAL_FACTOR, app(FreshnessPolicy::class)->freshProof($session->record, Operations::FACTOR_CHANGE)?->kind);
    }

    /**
     * An active session's proofs and first factor, read through the session
     * service and a contribution subject, come from the primary: a session and
     * a step-up the replica has not seen are read at once, and a revocation the
     * replica has not seen answers nothing, though the replica still holds the
     * session live with its proofs.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnActiveSessionsProofsAreReadFromThePrimary(): void
    {
        $now = CarbonImmutable::now()->startOfSecond();

        CarbonImmutable::setTestNow($now);

        $session = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        $key     = $session->record->getKey();
        $subject = new ContributionSubject(self::contextFor($session->identity), $session->identity, $session->principal, null, $session->record);

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('authentication_sessions')->count());
        self::assertSame(ProofKind::FIRST_FACTOR, $this->sessions()->firstFactor($key)?->kind);
        self::assertSame(ProofKind::FIRST_FACTOR, $subject->firstFactor()?->kind);

        CarbonImmutable::setTestNow($now->addMinute());

        self::assertTrue($this->sessions()->stepUp(self::adapterProof($session->identity, 'api', $key), self::requestClient())->isIssued());

        $kinds = static fn (array $proofs): array => array_map(static fn (RecordedProof $proof): ProofKind => $proof->kind, $proofs);

        self::assertSame([ProofKind::ADDITIONAL_FACTOR, ProofKind::FIRST_FACTOR], $kinds($this->sessions()->proofs($key)));
        self::assertSame([ProofKind::ADDITIONAL_FACTOR, ProofKind::FIRST_FACTOR], $kinds($subject->proofs()));

        $this->copyRowToReplica('authentication_sessions', $key);

        foreach (DB::connection(self::PRIMARY_CONNECTION)->table('authentication_proofs')->pluck('id') as $proof) {
            $this->copyRowToReplica('authentication_proofs', $proof);
        }

        DB::table('authentication_sessions')->where('id', $key)->update(['revoked_at' => $now, 'revoked_reason' => 'revoked']);

        self::assertNull(DB::connection(self::REPLICA_CONNECTION)->table('authentication_sessions')->value('revoked_at'));
        self::assertSame([[], null], [$this->sessions()->proofs($key), $this->sessions()->firstFactor($key)]);
        self::assertSame([[], null], [$subject->proofs(), $subject->firstFactor()]);
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
     * The package's own keys for the identity acting as itself on the guard.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Context\AuthenticationContext
     */
    private static function contextFor(Identity $identity): AuthenticationContext
    {
        $id = IdentifierCoercion::stringify($identity->getAuthIdentifier());

        return new AuthenticationContext(
            SubjectType::PERSON,
            'identity',
            $id,
            'identity',
            $id,
            null,
            null,
            'api',
            null,
            [],
            null,
            false,
            false,
            false,
            null,
            null,
            null,
            null,
        );
    }
}
