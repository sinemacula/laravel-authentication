<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\DeviceProof;
use SineMacula\Laravel\Authentication\Sessions\PendingSignIns;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Integration\Fixtures\RevocationLogDevice;
use Tests\Integration\Fixtures\RevocationLogIdentity;
use Tests\TestCase;

/**
 * Proves the device a client proves it holds is judged from the write
 * connection, for a device model that derives its revocation from another
 * table: a revocation only the primary has recorded yet keeps a sign-in, and
 * the completion of a sign-in held for a further factor, from continuing that
 * device while the replica lags behind.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeviceProof::class)]
#[CoversClass(PendingSignIns::class)]
final class ReplicaDeviceProofTest extends TestCase
{
    use InteractsWithLaggingReplica;

    /** @var string Guard the sessions are signed in on. */
    private const string GUARD = 'revocation_log';

    /** @var string Password of the seeded identity. */
    private const string PASSWORD = 'correct horse battery staple';

    /**
     * Freeze the clocks and create the identity and revocation log tables on
     * the primary and the replica.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($now);
        CarbonImmutable::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();

        $this->createOnPrimaryAndReplica('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        $this->createOnPrimaryAndReplica('device_revocations', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->uuid('device_id');
            $blueprint->timestamp('revoked_at');
        });

        $this->createOnPrimaryAndReplica('device_session_ends', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->uuid('device_id');
            $blueprint->dateTime('ended_at');
        });

        $identity = new RevocationLogIdentity;
        $identity->forceFill(['email' => 'ada@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)])->save();
    }

    /**
     * Release the clocks and remove the temporary database files.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();

        $this->removeLaggingReplicaFiles();
    }

    /**
     * A sign-in whose refresh token proves a device the primary has recorded as
     * revoked starts its session on a new device, leaving the revoked one as it
     * was.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASignInDoesNotContinueADeviceRevokedOnThePrimary(): void
    {
        $first = $this->signedIn($this->signIn());

        $this->revokeOnThePrimary($first);

        $again = $this->signedIn($this->signIn($first->tokens->refreshToken));

        self::assertTrue($again->deviceCreated);
        self::assertNotSame($first->device->getDeviceIdentifier(), $again->device->getDeviceIdentifier());
        $stored = DB::connection(self::PRIMARY_CONNECTION)->table('devices')->where('id', $first->device->getDeviceIdentifier())->value('refresh_key');

        self::assertSame($first->device->getRefreshKey(), $stored);
    }

    /**
     * A sign-in held for a further factor while its proven device was live does
     * not continue that device once the primary has recorded it as revoked:
     * completing it starts the session on a new device.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testACompletionDoesNotContinueADeviceRevokedOnThePrimary(): void
    {
        $first = $this->signedIn($this->signIn());

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

        $pending = $this->signIn($first->tokens->refreshToken)->pending;

        self::assertNotNull($pending);
        self::assertSame($first->device->getDeviceIdentifier(), $pending->provenDevice?->getDeviceIdentifier());

        $this->revokeOnThePrimary($first);

        $completed = $this->signedIn($this->guard()->sessions()->complete($pending->token));

        self::assertTrue($completed->deviceCreated);
        self::assertNotSame($first->device->getDeviceIdentifier(), $completed->device->getDeviceIdentifier());
    }

    /**
     * Configure the guard over the revocation log models and the lagging
     * read/write split.
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

        $config->set('auth.guards.' . self::GUARD, ['driver' => 'jwt', 'provider' => self::GUARD]);
        $config->set('auth.providers.' . self::GUARD, ['driver' => 'model', 'model' => RevocationLogIdentity::class]);
        $config->set('authentication.device.model', RevocationLogDevice::class);
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('authentication.timebox.credentials_microseconds', 1);
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
     * Sign the seeded identity in, proving the device the refresh token names
     * when one is given.
     *
     * @param  ?string  $refreshToken
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    private function signIn(#[\SensitiveParameter] ?string $refreshToken = null): SignInResult
    {
        $context = new SignInContext(new ClientContext('203.0.113.7', 'ReplicaTest/1.0'), refreshToken: $refreshToken);

        return $this->guard()->sessions()->signIn('password', ['email' => 'ada@example.test', 'password' => self::PASSWORD], $context);
    }

    /**
     * Record the session's device as revoked in the log on the primary only.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return void
     */
    private function revokeOnThePrimary(SignedInSession $session): void
    {
        DB::connection(self::PRIMARY_CONNECTION)->table('device_revocations')->insert([
            'device_id'  => $session->device->getDeviceIdentifier(),
            'revoked_at' => Carbon::now(),
        ]);

        self::assertSame(0, DB::connection(self::REPLICA_CONNECTION)->table('device_revocations')->count());
    }

    /**
     * The session a result started, asserting it started one.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInResult  $result
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     */
    private function signedIn(SignInResult $result): SignedInSession
    {
        self::assertNotNull($result->session, 'Expected a session; got ' . $result->status->value);

        return $result->session;
    }

    /**
     * Resolve the guard afresh.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guard(): JwtGuard
    {
        Auth::forgetGuards();

        $guard = Auth::manager()->guard(self::GUARD);

        self::assertInstanceOf(JwtGuard::class, $guard);

        return $guard;
    }
}
