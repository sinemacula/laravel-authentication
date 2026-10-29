<?php

declare(strict_types = 1);

namespace Tests\Integration\Verification;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Audience\GuardAudiencePolicy;
use SineMacula\Laravel\Authentication\Concerns\ProvidesIdentifierVerification;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\SignInFailureReason;
use SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;
use SineMacula\Laravel\Authentication\Verification\VerificationLinks;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithVerifiableIdentities;
use Tests\Integration\Fixtures\QueryingVerifiableIdentity;
use Tests\Integration\Fixtures\VerifiableIdentity;
use Tests\Integration\Fixtures\VerificationLogIdentity;
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
#[CoversClass(VerificationLinks::class)]
#[CoversTrait(ProvidesIdentifierVerification::class)]
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
     * An identity that reads its identifier with a query has it read from the
     * primary, both when the verifier compares it with the proof and when it
     * tells a repeat from a mismatch: a proof of the primary's address is
     * reported already verified while the replica still holds an older one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAQueriedIdentifierIsReadFromThePrimary(): void
    {
        DB::connection(self::REPLICA_CONNECTION)->table('verifiable_identities')->update(['email' => 'old@example.com']);

        $identity = (new QueryingVerifiableIdentity)->newFromBuilder(['id' => 1]);

        self::assertSame(IdentifierVerification::ALREADY_VERIFIED, app(IdentifierVerifier::class)->verify('api', $identity, 'email', 'ben@example.com'));
    }

    /**
     * Following a link checks its digest against the identifier the primary
     * holds, so a link for the current address still verifies while the replica
     * holds an older one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkIsCheckedAgainstTheIdentifierThePrimaryHolds(): void
    {
        Route::get('/verify', static fn (): array => [])->name('verify');

        $identity = WriteConnection::query(VerifiableIdentity::query())->findOrFail(1);
        $links    = app(VerificationLinks::class);
        $link     = $links->create('querying', $identity, 'email', 'verify');

        DB::connection(self::REPLICA_CONNECTION)->table('verifiable_identities')->update(['email' => 'old@example.com']);

        self::assertSame(IdentifierVerification::ALREADY_VERIFIED, $links->consume(Request::create($link)));
    }

    /**
     * A link created for an identity that reads its identifier with a query,
     * while the replica holds an older address, is signed for the address the
     * primary holds, so following it verifies.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALinkIsSignedForTheIdentifierThePrimaryHolds(): void
    {
        Route::get('/verify', static fn (): array => [])->name('verify');

        DB::connection(self::PRIMARY_CONNECTION)->table('verifiable_identities')->update(['email_verified_at' => null]);
        DB::connection(self::REPLICA_CONNECTION)->table('verifiable_identities')->update(['email' => 'old@example.com']);

        $identity = (new QueryingVerifiableIdentity)->newFromBuilder(['id' => 1]);
        $links    = app(VerificationLinks::class);
        $link     = $links->create('querying', $identity, 'email', 'verify');

        self::assertSame(IdentifierVerification::VERIFIED, $links->consume(Request::create($link)));
        self::assertNotNull(DB::connection(self::PRIMARY_CONNECTION)->table('verifiable_identities')->value('email_verified_at'));
    }

    /**
     * Reading a verification time that an accessor derives with a query reads
     * the primary, even when the identity is asked directly rather than by the
     * package.
     *
     * @return void
     */
    public function testAVerificationTimeAnAccessorQueriesIsReadFromThePrimary(): void
    {
        $this->createOnPrimaryAndReplica('identifier_verifications', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->dateTime('verified_at');
        });

        DB::connection(self::PRIMARY_CONNECTION)->table('verifiable_identities')->update(['email_verified_at' => null]);
        DB::connection(self::PRIMARY_CONNECTION)->table('identifier_verifications')->insert(['identity_id' => 1, 'verified_at' => '2027-01-01 00:00:00']);

        $identity = (new VerificationLogIdentity)->newFromBuilder(['id' => 1, 'email' => 'ben@example.com', 'email_verified_at' => null]);

        self::assertTrue($identity->hasVerifiedIdentifier('email'));
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
        $config->set('auth.guards.querying', ['driver' => 'jwt', 'provider' => 'querying']);
        $config->set('auth.providers.querying', ['driver' => 'model', 'model' => QueryingVerifiableIdentity::class]);
    }
}
