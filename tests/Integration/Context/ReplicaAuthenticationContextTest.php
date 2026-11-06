<?php

declare(strict_types = 1);

namespace Tests\Integration\Context;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Context\ContextBuilder;
use SineMacula\Laravel\Authentication\Context\ContextContributors;
use SineMacula\Laravel\Authentication\Context\ContributionSubject;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithExternalSignIns;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithProofs;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Context\ScriptedContributor;
use Tests\TestCase;

/**
 * Integration tests of the authentication context over a read/write split whose
 * replica lags: the session's proofs and its provenance are read from the
 * primary, so a step-up just made counts in the request that made it and a
 * session just established through a provider has its provenance.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContextBuilder::class)]
#[CoversClass(ContributionSubject::class)]
final class ReplicaAuthenticationContextTest extends TestCase
{
    use InteractsWithExternalSignIns, InteractsWithLaggingReplica, InteractsWithProofs, InteractsWithSessions;

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

        CarbonImmutable::setTestNow(CarbonImmutable::now()->startOfSecond());

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
     * A step-up the replica has not seen counts in the context of the request
     * that made it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAStepUpTheReplicaHasNotSeenCounts(): void
    {
        $session = $this->sessions()->signIn('password', self::credentials(), self::requestContext())->session;

        self::assertNotNull($session);

        $this->authenticated($session);

        self::assertFalse(Auth::context()?->mfa);

        CarbonImmutable::setTestNow(CarbonImmutable::now()->addMinute());

        self::assertTrue(Auth::sessions('api')->stepUp(self::adapterProof($session->identity, 'api', $session->record->getKey()), self::requestClient())->isIssued());
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('authentication_proofs')->count());
        $context = Auth::context();

        self::assertNotNull($context);
        self::assertSame([true, ['pwd', 'otp', 'mfa']], [$context->mfa, $context->amr]);
    }

    /**
     * A session a provider established, which the replica has not seen, has its
     * provenance for a contributor that asks.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProvenanceTheReplicaHasNotSeenIsRead(): void
    {
        $identity = $this->seedIdentity('external@example.test');
        $session  = $this->sessions()->signInExternally($this->linkedResult($identity), self::requestContext())->session;

        self::assertNotNull($session);

        $contributor = new ScriptedContributor(static fn (ContributionSubject $subject): array => ['connection_id' => $subject->provenance()?->connectionId]);

        app()->instance('tests.context.sso', $contributor);
        app(ContextContributors::class)->register('sso', 'tests.context.sso');

        $this->authenticated($session);

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('authentication_provenance')->count());
        self::assertSame('connection-7', Auth::context()?->get('sso.connection_id'));
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
     * Serve a request bearing the session's access token on the `api` guard,
     * the default, and authenticate it.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return void
     */
    private function authenticated(SignedInSession $session): void
    {
        app()->instance('request', Request::create('/context', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $session->tokens->accessToken->reveal()]));

        Auth::forgetGuards();
        Auth::shouldUse('api');

        self::assertTrue(Auth::guard('api')->check());
    }
}
