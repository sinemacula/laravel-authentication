<?php

declare(strict_types = 1);

namespace Tests\Integration\Proofs;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\FreshnessPolicy;
use SineMacula\Laravel\Authentication\Freshness\ConfiguredFreshness;
use SineMacula\Laravel\Authentication\Freshness\Operations;
use SineMacula\Laravel\Authentication\Proofs\AuthenticationClaims;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\SessionProofs;
use SineMacula\Laravel\Authentication\Sessions\SessionStepUp;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Integration tests of a session's proofs over a read/write split whose replica
 * lags: every read of them goes to the primary, so a proof just written counts
 * for the claims, for freshness and for the next step-up straight away.
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
     * Remove the temporary database files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
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
        $session = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('authentication_proofs')->count());
        self::assertSame(['pwd'], AuthenticationClaims::forSession($session->record)->methods);
        self::assertSame(ProofKind::FIRST_FACTOR, app(FreshnessPolicy::class)->freshProof($session->record, Operations::IDENTIFIER_CHANGE)?->kind);

        self::assertTrue($this->sessions()->stepUp(self::adapterProof($session->identity, 'api', $session->record->getKey()))->isIssued());

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('authentication_proofs')->count());
        self::assertSame(['pwd', 'otp', 'mfa'], AuthenticationClaims::forSession($session->record)->methods);
        self::assertSame(ProofKind::ADDITIONAL_FACTOR, app(FreshnessPolicy::class)->freshProof($session->record, Operations::FACTOR_CHANGE)?->kind);
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
}
