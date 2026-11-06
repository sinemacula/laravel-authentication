<?php

declare(strict_types = 1);

namespace Tests\Integration\Listeners;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\PasskeyRemoved;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Listeners\RevokeSessionsOnPasskeyRemoval;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Database\ShippedMigrations;
use Tests\TestCase;

/**
 * Proves `RevokeSessionsOnPasskeyRemoval` reads the identity on the write
 * connection: an identity created moments ago, which only the primary holds
 * yet, has every session ended when it removes a passkey while the replica lags
 * behind.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevokeSessionsOnPasskeyRemoval::class)]
final class RevokeSessionsOnPasskeyRemovalTest extends TestCase
{
    use InteractsWithLaggingReplica, InteractsWithPasskeys, InteractsWithSessions;

    /**
     * Create the identity table on the primary and the replica, and register
     * the listener.
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

        Event::listen(PasskeyRemoved::class, RevokeSessionsOnPasskeyRemoval::class);
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
     * Removing a passkey of an identity only the primary holds ends every
     * session it has.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityOnlyThePrimaryHoldsHasItsSessionsRevoked(): void
    {
        $identity = $this->seedIdentity();
        $passkey  = $this->registerPasskey($identity);

        self::assertTrue($this->signInWithPasskey()->isSignedIn());
        self::assertTrue($this->sessions()->signIn('password', self::credentials(), self::requestContext())->isSignedIn());
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('integration_identities')->count());
        self::assertTrue(Auth::passkeys('api')->remove($identity, $passkey->id, self::requestClient())->isRemoved());

        self::assertSame(['factor_removed', 'factor_removed'], DB::connection(self::PRIMARY_CONNECTION)->table('authentication_sessions')->pluck('revoked_reason')->all());
    }

    /**
     * Configure the guards and their relying party over a lagging read/write
     * split.
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
        self::configurePasskeys($config);

        $this->configureLaggingReplica($config);
    }

    /**
     * Create the package tables, the passkey tables included, on the primary
     * and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica();

        /** @var \Illuminate\Database\DatabaseManager $manager */
        $manager = app(DatabaseManager::class);

        foreach (['2026_04_06_000004_create_passkeys_table.php', '2026_04_06_000005_create_passkey_challenges_table.php'] as $file) {

            foreach ([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {
                $manager->setDefaultConnection($connection);
                ShippedMigrations::up($file);
            }
        }

        $manager->setDefaultConnection(self::SPLIT_CONNECTION);
    }
}
