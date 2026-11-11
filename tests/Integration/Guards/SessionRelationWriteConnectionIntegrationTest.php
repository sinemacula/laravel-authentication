<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\DatabaseManager;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Guards\Concerns\VerifiesPinnedContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Integration\Fixtures\GrantedSessionsIdentity;
use Tests\TestCase;

/**
 * Tests that an identity's `sessions()` relation is built on the write
 * connection, not a lagging replica.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
#[CoversTrait(VerifiesPinnedContext::class)]
final class SessionRelationWriteConnectionIntegrationTest extends TestCase
{
    use InteractsWithLaggingReplica, InteractsWithSessionRecords;

    /** @var string Plaintext password of the seeded identity. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var array{email: string, password: string} Credentials of the seeded identity. */
    private const array CREDENTIALS = ['email' => 'granted@example.test', 'password' => self::PASSWORD];

    /**
     * Freeze the clocks and create the identity table on the primary and the
     * replica.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

        $this->createOnPrimaryAndReplica('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });
    }

    /**
     * Release the frozen clocks and remove the temporary database files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * A bearer token stops authenticating once its session's grant is withdrawn
     * on the primary.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRejectsASessionWhoseGrantIsWithdrawnOnThePrimary(): void
    {
        [$identity, $session] = $this->seedGrantedSession();

        $token   = $this->authManager()->jwt('api')->issueAccessToken($identity, $identity, null, $session)->reveal();
        $request = Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]);

        self::assertTrue($identity->is($this->guardForRequest($request)->user()));

        $this->withdrawGrant($session);

        self::assertNull($this->guardForRequest($request)->user());
    }

    /**
     * Pinning a session whose grant is withdrawn on the primary fails the
     * attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptRejectsAPinnedSessionWhoseGrantIsWithdrawnOnThePrimary(): void
    {
        [, $session] = $this->seedGrantedSession();

        self::assertTrue($this->guardForRequest(Request::create('/sign-in', 'POST'))->attempt(self::CREDENTIALS, null, $session));

        $this->withdrawGrant($session);

        $guard = $this->guardForRequest(Request::create('/sign-in', 'POST'));

        self::assertFalse($guard->attempt(self::CREDENTIALS, null, $session));
        self::assertFalse($guard->hasUser());
    }

    /**
     * A relation that fails to build propagates the error and restores replica
     * reads.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBearerRestoresReplicaReadsWhenBuildingTheRelationFails(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity);

        Schema::connection(self::REPLICA_CONNECTION)->create('session_grants', static function (Blueprint $blueprint): void {
            $blueprint->unsignedInteger('identity_id');
            $blueprint->uuid('session_id');
        });

        $resolver = Model::getConnectionResolver();
        $token    = $this->authManager()->jwt('api')->issueAccessToken($identity, $identity, null, $session)->reveal();

        try {
            $this->guardForRequest(Request::create('/me', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $token]))->user();

            self::fail('Building the relation should have failed on the writer.');
        } catch (\Throwable $exception) {
            self::assertInstanceOf(QueryException::class, $exception);
            self::assertStringContainsString('session_grants', $exception->getMessage());
        }

        self::assertSame($resolver, Model::getConnectionResolver());
        self::assertInstanceOf(DatabaseManager::class, $resolver);
        self::assertSame(0, DB::connection(self::SPLIT_CONNECTION)->table('stub_principals')->count());
    }

    /**
     * Configure the lagging split connection and the JWT guard over the
     * identity whose relation reads its grants.
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

        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities', 'application' => ['methods' => ['password']]]);
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => GrantedSessionsIdentity::class]);

        // Failed attempts wait out the timebox; keep it short.
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Create the package tables on the primary and the replica instead of
     * migrating the default connection.
     *
     * @return void
     */
    #[\Override]
    protected function defineDatabaseMigrations(): void
    {
        $this->migratePackageTablesOnPrimaryAndReplica();
    }

    /**
     * Seed an identity and a session on the primary and the replica, with a
     * grant for the session on both.
     *
     * @return array{0: \Tests\Integration\Fixtures\GrantedSessionsIdentity, 1: \SineMacula\Laravel\Authentication\Models\Session}
     */
    private function seedGrantedSession(): array
    {
        $this->createOnPrimaryAndReplica('session_grants', static function (Blueprint $blueprint): void {
            $blueprint->unsignedInteger('identity_id');
            $blueprint->uuid('session_id');
        });

        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity);

        $this->copyRowToReplica('stub_principals', $identity->getKey());
        $this->copyRowToReplica('authentication_sessions', $session->getKey());

        foreach ([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {
            DB::connection($connection)->table('session_grants')->insert([
                'identity_id' => $identity->getKey(),
                'session_id'  => $session->getKey(),
            ]);
        }

        return [$identity, $session];
    }

    /**
     * Write an identity through the split connection, so it exists on the
     * primary only.
     *
     * @return \Tests\Integration\Fixtures\GrantedSessionsIdentity
     */
    private function seedIdentity(): GrantedSessionsIdentity
    {
        $identity = new GrantedSessionsIdentity;
        $identity->forceFill([
            'email'    => self::CREDENTIALS['email'],
            'password' => app(Hasher::class)->make(self::PASSWORD),
        ])->save();

        return $identity;
    }

    /**
     * Write a session for the identity through the split connection, so it
     * exists on the primary only.
     *
     * @param  \Tests\Integration\Fixtures\GrantedSessionsIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function seedSession(GrantedSessionsIdentity $identity): Session
    {
        $session = new Session;
        $session->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => GrantedSessionsIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => (string) $identity->getKey(), // @phpstan-ignore cast.string
        ])->save();

        return $session;
    }

    /**
     * Withdraw the session's grant through the split connection, so the replica
     * still holds it.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\Session  $session
     * @return void
     */
    private function withdrawGrant(Session $session): void
    {
        DB::connection(self::SPLIT_CONNECTION)->table('session_grants')->where('session_id', $session->getKey())->delete();
    }

    /**
     * Resolve the package auth manager with no cached guards.
     *
     * @return \SineMacula\Laravel\Authentication\AuthManager
     */
    private function authManager(): AuthManager
    {
        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $manager->forgetGuards();

        return $manager;
    }

    /**
     * Resolve a fresh JWT guard bound to the supplied request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guardForRequest(Request $request): JwtGuard
    {
        app()->instance('request', $request);

        $guard = $this->authManager()->guard('api');

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
