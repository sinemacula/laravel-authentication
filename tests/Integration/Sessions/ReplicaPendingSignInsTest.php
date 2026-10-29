<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Sessions\PendingSignIns;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Proves a pending sign-in is read from the write connection: one issued
 * moments ago, which only the primary holds yet, is found and completed while
 * the replica lags behind.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingSignIns::class)]
final class ReplicaPendingSignInsTest extends TestCase
{
    use InteractsWithLaggingReplica, InteractsWithSessions;

    /**
     * Create the identity table on the primary and the replica, seed an
     * identity both hold, and require a further factor of every sign-in.
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

        app()->instance(AdditionalFactorPolicy::class, new class implements AdditionalFactorPolicy {
            /**
             * Always require a further factor.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return bool
             */
            #[\Override]
            public function requiresAdditionalFactor(AdditionalFactorContext $context): bool
            {
                return true;
            }
        });
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
     * A pending sign-in only the primary holds is looked up and completed into
     * a session, straight after it was issued.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPendingSignInTheReplicaHasNotSeenIsFoundAndCompleted(): void
    {
        $pending = $this->sessions()->signIn('password', self::credentials())->pending;

        self::assertNotNull($pending);
        self::assertSame(1, PendingSignIn::query()->useWritePdo()->count());
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('pending_sign_ins')->count());

        self::assertNotNull($this->sessions()->pending($pending->token));
        self::assertTrue($this->sessions()->complete($pending->token)->isSignedIn());
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
