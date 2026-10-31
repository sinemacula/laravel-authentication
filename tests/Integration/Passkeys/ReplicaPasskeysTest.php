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
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Proves passkeys and their challenges are read from the write connection: a
 * passkey registered and challenges issued moments ago, which only the primary
 * holds yet, are found while the replica lags behind, by every ceremony and by
 * the listing.
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
     * A passkey only the primary holds, registered through a challenge only the
     * primary held, is listed, offered to a factor ceremony, verified as a
     * factor, and signs its owner in, each straight after the write before it.
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

        $factor = Auth::passkeys('api')->factorOptions($identity);

        self::assertCount(1, (array) $factor->options['allowCredentials']);
        self::assertTrue(Auth::passkeys('api')->verifyFactor($identity, $factor->challengeId, $this->authenticator()->get($factor->options))->isVerified());

        self::assertTrue($this->signInWithPasskey()->isSignedIn());
        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('passkey_challenges')->count());
    }

    /**
     * A later registration reuses the handle and excludes the passkey that only
     * the primary holds.
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
     * A passkey without a counter that the primary removed while its sign-in
     * was in flight signs nobody in, though the replica still holds it.
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

            $migration = require __DIR__ . '/../../../database/migrations/' . $file;

            foreach ([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {
                $manager->setDefaultConnection($connection);
                $migration->up();
            }
        }

        $manager->setDefaultConnection(self::SPLIT_CONNECTION);
    }

    /**
     * Register a passkey for the seeded identity through the split, so only the
     * primary holds it, and return the identity.
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
