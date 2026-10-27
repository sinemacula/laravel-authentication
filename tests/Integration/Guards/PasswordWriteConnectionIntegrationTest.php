<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Integration\Fixtures\SeparatePasswordIdentity;
use Tests\TestCase;

/**
 * Proves that the password hash a sign-in is checked against is read from the
 * write connection, so a hash a lagging replica still holds cannot admit a
 * password the primary has already replaced.
 *
 * The identity keeps its hash in `identity_passwords`, read by its own password
 * getter. The default connection is a read/write split whose replica lags
 * behind the primary.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ModelProvider::class)]
final class PasswordWriteConnectionIntegrationTest extends TestCase
{
    use InteractsWithLaggingReplica;

    /** @var string Password the identity had before the reset. */
    private const string OLD_PASSWORD = 'correct horse battery staple';

    /** @var string Password the identity was reset to on the primary. */
    private const string NEW_PASSWORD = 'tr0ub4dor and three';

    /** @var string Email of the seeded identity. */
    private const string EMAIL = 'reset@example.test';

    /**
     * Create the identity table on the primary and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createOnPrimaryAndReplica('separate_password_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->timestamps();
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
     * After a reset on the primary that the replica has not seen, the provider
     * rejects the old password and accepts the new one.
     *
     * @return void
     */
    public function testValidateCredentialsChecksTheHashOnThePrimary(): void
    {
        $identity = $this->seedResetIdentity();
        $provider = new ModelProvider(app(Hasher::class), SeparatePasswordIdentity::class);

        self::assertFalse($provider->validateCredentials($identity, ['password' => self::OLD_PASSWORD]));
        self::assertTrue($provider->validateCredentials($identity, ['password' => self::NEW_PASSWORD]));
    }

    /**
     * Signing in over HTTP with the password the primary has replaced is
     * refused, although the replica still holds its hash, and the new password
     * signs in.
     *
     * @return void
     */
    public function testSignInRejectsThePasswordReplacedOnThePrimaryWhileTheReplicaLags(): void
    {
        $identity = $this->seedResetIdentity();

        Route::post('/sign-in', static fn (): array => [
            'signed_in' => Auth::guard('api')->attempt(['email' => self::EMAIL, 'password' => request()->string('password')->toString()]),
            'identity'  => Auth::guard('api')->id(),
        ]);

        $this->postJson('/sign-in', ['password' => self::OLD_PASSWORD])
            ->assertOk()
            ->assertExactJson(['signed_in' => false, 'identity' => null]);

        $this->postJson('/sign-in', ['password' => self::NEW_PASSWORD])
            ->assertOk()
            ->assertExactJson(['signed_in' => true, 'identity' => $identity->getKey()]);
    }

    /**
     * A password getter whose query fails on the writer propagates the error,
     * and afterwards reads go back to the replica through the original
     * connection resolver.
     *
     * @return void
     */
    public function testValidateCredentialsRestoresReplicaReadsWhenReadingTheHashFails(): void
    {
        Schema::connection(self::REPLICA_CONNECTION)->create('identity_passwords', static function (Blueprint $blueprint): void {
            $blueprint->unsignedInteger('identity_id');
            $blueprint->string('hash');
        });

        $identity = new SeparatePasswordIdentity;
        $identity->forceFill(['email' => self::EMAIL])->save();

        $provider = new ModelProvider(app(Hasher::class), SeparatePasswordIdentity::class);
        $resolver = Model::getConnectionResolver();

        try {
            $provider->validateCredentials($identity, ['password' => self::OLD_PASSWORD]);

            self::fail('Reading the hash should have failed on the writer.');
        } catch (\Throwable $exception) {
            self::assertInstanceOf(QueryException::class, $exception);
            self::assertStringContainsString('identity_passwords', $exception->getMessage());
        }

        self::assertSame($resolver, Model::getConnectionResolver());
        self::assertInstanceOf(DatabaseManager::class, $resolver);
        self::assertSame(0, DB::connection(self::SPLIT_CONNECTION)->table('separate_password_identities')->count());
    }

    /**
     * Configure the lagging split connection and the JWT guard over the
     * identity that keeps its hash apart.
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

        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities']);
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => SeparatePasswordIdentity::class]);

        // Failed attempts wait out the timebox; keep it short.
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Create the devices table on the primary and the replica instead of
     * migrating the default connection.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migrateDevicesOnPrimaryAndReplica();
    }

    /**
     * Seed an identity on the primary and the replica whose hash is for the old
     * password on both, then reset it to the new password on the primary only.
     *
     * @return \Tests\Integration\Fixtures\SeparatePasswordIdentity
     */
    private function seedResetIdentity(): SeparatePasswordIdentity
    {
        $this->createOnPrimaryAndReplica('identity_passwords', static function (Blueprint $blueprint): void {
            $blueprint->unsignedInteger('identity_id');
            $blueprint->string('hash');
        });

        $identity = new SeparatePasswordIdentity;
        $identity->forceFill(['email' => self::EMAIL])->save();

        $this->copyRowToReplica('separate_password_identities', $identity->getKey());

        $hasher = app(Hasher::class);

        foreach ([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {
            DB::connection($connection)->table('identity_passwords')->insert([
                'identity_id' => $identity->getKey(),
                'hash'        => $hasher->make(self::OLD_PASSWORD),
            ]);
        }

        DB::connection(self::SPLIT_CONNECTION)
            ->table('identity_passwords')
            ->where('identity_id', $identity->getKey())
            ->update(['hash' => $hasher->make(self::NEW_PASSWORD)]);

        return $identity;
    }
}
