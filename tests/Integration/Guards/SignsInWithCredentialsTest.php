<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Guards\Concerns\SignsInWithCredentials;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Requirements\Requirement;
use SineMacula\Laravel\Authentication\Requirements\RequirementPart;
use Tests\Concerns\InteractsWithLaggingReplica;
use Tests\Integration\Fixtures\SeparatePasswordIdentity;
use Tests\TestCase;

/**
 * Integration tests for asking the additional-factor policy on `attempt()`
 * against a read/write split whose replica lags behind its primary: the policy
 * is asked on the identity's writer, so a factor enrolled on the primary that
 * the replica has not seen yet still holds the attempt back. It is told of the
 * password as the attempt's first factor.
 *
 * The policy asks for a further factor only when its read on the identity's
 * connection finds a row written through the split connection, which exists on
 * the primary only: a refused attempt shows the read was served by the writer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(SignsInWithCredentials::class)]
final class SignsInWithCredentialsTest extends TestCase
{
    use InteractsWithLaggingReplica;

    /** @var string The identity's email address. */
    private const string EMAIL = 'ada@example.test';

    /** @var string The identity's password. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var string Table of the factors the policy reads. */
    private const string FACTORS = 'factors';

    /**
     * Create the identity, its password and the factors table on the primary
     * and the replica, seed the identity on both, and bind a policy that asks
     * for a factor only when the identity's connection finds one.
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
        $this->createOnPrimaryAndReplica('identity_passwords', static function (Blueprint $blueprint): void {
            $blueprint->unsignedInteger('identity_id');
            $blueprint->string('hash');
        });
        $this->createOnPrimaryAndReplica(self::FACTORS, static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
        });

        $identity = new SeparatePasswordIdentity;
        $identity->forceFill(['email' => self::EMAIL])->save();

        $this->copyRowToReplica('separate_password_identities', $identity->getKey());

        $hash = app(Hasher::class)->make(self::PASSWORD);

        foreach ([self::PRIMARY_CONNECTION, self::REPLICA_CONNECTION] as $connection) {
            DB::connection($connection)->table('identity_passwords')->insert(['identity_id' => $identity->getKey(), 'hash' => $hash]);
        }

        $this->app?->instance(AdditionalFactorPolicy::class, new class implements AdditionalFactorPolicy {
            /**
             * Ask for a further factor when the identity's connection finds one
             * enrolled.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                return DB::connection('split')->table('factors')->exists() ? new Requirement(new RequirementPart) : new Requirement;
            }
        });
    }

    /**
     * Remove the temporary primary and replica files.
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
     * A factor enrolled on the primary only is found, so the attempt is held
     * back for it, and the identity's connection reads from its replica again
     * afterwards.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePolicyIsAskedOnTheIdentitysWriter(): void
    {
        DB::connection(self::SPLIT_CONNECTION)->table(self::FACTORS)->insert(['id' => 1]);

        self::assertFalse(Auth::guard('api')->attempt(['email' => self::EMAIL, 'password' => self::PASSWORD]));
        self::assertFalse(DB::connection(self::SPLIT_CONNECTION)->table(self::FACTORS)->exists());
    }

    /**
     * With no factor on the primary either, the policy asks for nothing and the
     * attempt signs in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testWithoutAFactorTheAttemptSignsIn(): void
    {
        self::assertTrue(Auth::guard('api')->attempt(['email' => self::EMAIL, 'password' => self::PASSWORD]));
    }

    /**
     * The policy is told of the password as the attempt's first factor: a
     * password channel and the `pwd` method.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThePolicyIsToldOfThePasswordAsTheFirstFactor(): void
    {
        /** @var \ArrayObject<int, \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext> $told */
        $told = new \ArrayObject;

        $this->app?->instance(AdditionalFactorPolicy::class, new class ($told) implements AdditionalFactorPolicy {
            /**
             * Constructor.
             *
             * @param  \ArrayObject<int, \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext>  $told
             */
            public function __construct(

                /** The contexts the policy was asked with. */
                private readonly \ArrayObject $told,
            ) {}

            /**
             * Record the context and ask for nothing.
             *
             * @param  \SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext  $context
             * @return \SineMacula\Laravel\Authentication\Requirements\Requirement
             */
            #[\Override]
            public function requirementFor(AdditionalFactorContext $context): Requirement
            {
                $this->told->append($context);

                return new Requirement;
            }
        });

        self::assertTrue(Auth::guard('api')->attempt(['email' => self::EMAIL, 'password' => self::PASSWORD]));
        self::assertCount(1, $told);
        self::assertInstanceOf(AdditionalFactorContext::class, $told[0]);

        $firstFactor = $told[0]->firstFactor;

        self::assertSame([ChannelKind::PASSWORD, ['pwd']], [$firstFactor->channel->kind, $firstFactor->methods]);
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

        $config = app(ConfigRepository::class);

        $this->configureLaggingReplica($config);

        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities', 'application' => ['methods' => ['password']]]);
        $config->set('auth.providers.identities', ['driver' => 'model', 'model' => SeparatePasswordIdentity::class]);
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
}
