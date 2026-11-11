<?php

declare(strict_types = 1);

namespace Tests\Integration\Passkeys;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyChallenges;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyCredentials;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Database\ShippedMigrations;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Proves passkeys and their challenges are read from the write connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyChallenges::class)]
#[CoversClass(PasskeyCredentials::class)]
final class ReplicaPasskeysTest extends TestCase
{
    use InteractsWithLaggingReplica, InteractsWithPasskeys, InteractsWithSessions;

    /**
     * Create the identity table on the primary and the replica, and seed an
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
     * Passkeys and challenges only the primary holds are found by every
     * ceremony and the listing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPasskeysAndChallengesTheReplicaHasNotSeenAreFound(): void
    {
        $identity = $this->registered();

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('passkeys')->count());
        self::assertCount(1, Auth::passkeys('api')->passkeys($identity));
        self::assertCount(1, Auth::passkeys('api')->credentialIds($identity));

        $factor = self::factorCeremony(Auth::passkeys('api'), $identity);

        self::assertCount(1, (array) $factor->options['allowCredentials']);
        self::assertTrue(self::verifyPasskeyFactor($identity, $factor->challengeId, $this->authenticator()->get($factor->options))->isVerified());

        self::assertTrue($this->signInWithPasskey()->isSignedIn());
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('passkey_challenges')->whereNull('consumed_at')->count());
    }

    /**
     * A later registration reuses the handle and excludes the passkey only the
     * primary holds.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALaterRegistrationSeesThePasskeyOnlyThePrimaryHolds(): void
    {
        $identity = $this->registered();
        $options  = Auth::passkeys('api')->registrationOptions($identity, self::USER_NAME);

        self::assertCount(1, (array) $options->options['excludeCredentials']);
        self::assertSame(DB::connection(self::PRIMARY_CONNECTION)->table('passkeys')->value('user_handle'), ((array) $options->options['user'])['id']);
    }

    /**
     * A passkey the primary removed mid sign-in signs nobody in, though the
     * replica still holds it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPasskeyThePrimaryRemovedIsNotUsed(): void
    {
        $this->authenticator()->counterStep = 0;

        $this->registered();
        $this->copyRowToReplica('passkeys', DB::connection(self::PRIMARY_CONNECTION)->table('passkeys')->value('id'));

        IntegrationIdentity::retrieved(static function (): void {
            DB::connection(self::PRIMARY_CONNECTION)->table('passkeys')->delete();
        });

        self::assertFalse($this->signInWithPasskey()->isSignedIn());
        self::assertSame(1, DB::connection(self::REPLICA_CONNECTION)->table('passkeys')->count());
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
     * Create the package tables on the primary and the replica.
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

    /**
     * Register a passkey for the seeded identity so only the primary holds it.
     *
     * @return \Tests\Integration\Fixtures\IntegrationIdentity
     *
     * @throws \Throwable
     */
    private function registered(): IntegrationIdentity
    {
        $identity = IntegrationIdentity::query()->useWritePdo()->firstOrFail();

        $this->registerPasskey($identity);

        return $identity;
    }
}
