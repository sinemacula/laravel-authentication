<?php

declare(strict_types = 1);

namespace Tests\Integration\Verification;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Audience\GuardAudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithVerifiableIdentities;
use Tests\Integration\Fixtures\QueryingVerifiableIdentity;
use Tests\Integration\Fixtures\VerifiableIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainPrincipalFixture;

/**
 * Proves verified state is read from the write connection: a verification the
 * primary holds and the replica has not yet seen is honoured by the verifier's
 * re-read and by the sign-in gate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentifierVerifier::class)]
#[CoversClass(GuardAudiencePolicy::class)]
final class ReplicaIdentifierVerifierTest extends TestCase
{
    use InteractsWithLaggingReplica, InteractsWithVerifiableIdentities;

    /**
     * Create the identities table on the primary and the replica, with an
     * unverified identity on both and its verification on the primary only.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::createVerifiableIdentitiesTable(self::PRIMARY_CONNECTION);
        self::createVerifiableIdentitiesTable(self::REPLICA_CONNECTION);

        $identity = self::seedVerifiableIdentity();

        $this->copyRowToReplica('verifiable_identities', $identity->getKey());

        DB::connection(self::PRIMARY_CONNECTION)->table('verifiable_identities')->update(['email_verified_at' => '2027-01-01 00:00:00']);
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
     * Verifying an identity loaded before the verification is reported as
     * already verified, from the primary, not as a mismatch the replica would
     * suggest.
     *
     * @return void
     */
    public function testAlreadyVerifiedIsReadFromThePrimary(): void
    {
        $stale = DB::connection(self::REPLICA_CONNECTION)->table('verifiable_identities')->first();

        self::assertNotNull($stale);
        self::assertNull($stale->email_verified_at);

        $identity = (new VerifiableIdentity)->newFromBuilder((array) $stale);

        self::assertSame(IdentifierVerification::ALREADY_VERIFIED, app(IdentifierVerifier::class)->verify('api', $identity, 'email', 'ben@example.com'));
    }

    /**
     * The sign-in gate asks the identity inside the write-connection window, so
     * an identity that queries for its verification reads the primary.
     *
     * @return void
     */
    public function testGateReadsTheVerificationFromThePrimary(): void
    {
        $identity = (new QueryingVerifiableIdentity)->newFromBuilder(['id' => 1]);

        self::assertNull(app(AudiencePolicy::class)->admit('api', $identity, new PlainPrincipalFixture(1), 'email'));

        DB::connection(self::PRIMARY_CONNECTION)->table('verifiable_identities')->update(['email_verified_at' => null]);

        self::assertSame(SignInFailureReason::IDENTIFIER_UNVERIFIED, app(AudiencePolicy::class)->admit('api', $identity, new PlainPrincipalFixture(1), 'email'));
    }

    /**
     * Configure the lagging replica and a guard that requires verified
     * identifiers.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        /** @var \Illuminate\Config\Repository $config */
        $config = app(ConfigRepository::class);

        $this->configureLaggingReplica($config);

        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'users', 'audience' => ['require_verified_identifier' => true]]);
    }
}
