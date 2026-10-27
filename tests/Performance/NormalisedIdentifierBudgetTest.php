<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Hashing\BcryptHasher;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Providers\ModelProvider;
use Tests\Integration\Fixtures\NormalisedEmailIdentity;

/**
 * Query-budget and timing contracts for designated identifiers: normalising a
 * lookup adds no query, an identifier that cannot be one costs none while a
 * sign-in with it still waits out the timebox, and a rehash is one write or
 * nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ModelProvider::class)]
#[CoversClass(JwtGuard::class)]
final class NormalisedIdentifierBudgetTest extends PerformanceContractTestCase
{
    /** @var string Guard over the identity. */
    private const string GUARD = 'normalised_api';

    /** @var string Plaintext password of the seeded identity. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var int Timebox for the timing contract, in microseconds. */
    private const int TIMEBOX_MICROSECONDS = 150000;

    /**
     * Create the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('normalised_email_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->nullable()->unique();
            $blueprint->string('name');
            $blueprint->string('password');
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('normalised_email_identities');

        parent::tearDown();
    }

    /**
     * Looking an identity up by any casing of a designated identifier costs the
     * one read a lookup always costs, and an identifier that cannot be one
     * costs none.
     *
     * @return void
     */
    public function testNormalisedLookupUsesOneReadAndARejectedOneNone(): void
    {
        $this->seedIdentity(10);

        $provider = $this->provider();

        self::assertNotNull($this->assertQueryBudget(1, 0, static fn (): mixed => $provider->retrieveByCredentials(['email' => ' SIGNER@Example.test '])));
        self::assertNull($this->assertQueryBudget(0, 0, static fn (): mixed => $provider->retrieveByCredentials(['email' => '   '])));
    }

    /**
     * A sign-in with an identifier that cannot be one still waits out the
     * timebox, so skipping the lookup does not make it answer faster than one
     * for an unknown account.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSignInWithARejectedIdentifierWaitsOutTheTimebox(): void
    {
        config()->set('authentication.timebox.credentials_microseconds', self::TIMEBOX_MICROSECONDS);

        $guard   = $this->freshJwtGuard(self::GUARD);
        $started = hrtime(true);

        self::assertFalse($guard->attempt(['email' => '   ', 'password' => self::PASSWORD]));
        self::assertGreaterThanOrEqual(self::TIMEBOX_MICROSECONDS * 1000, hrtime(true) - $started);
    }

    /**
     * Rehashing an outdated hash is exactly one write and no read; a current
     * hash costs nothing.
     *
     * @return void
     */
    public function testRehashIsOneWriteOrNothing(): void
    {
        $provider = $this->provider();
        $outdated = $this->seedIdentity(4);

        $this->assertQueryBudget(0, 1, static fn () => $provider->rehashPasswordIfRequired($outdated, ['password' => self::PASSWORD]));
        $this->assertQueryBudget(0, 0, static fn () => $provider->rehashPasswordIfRequired($outdated, ['password' => self::PASSWORD]));
    }

    /**
     * Configure a guard over the identity, with a timebox short enough for the
     * budget contracts.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.guards.' . self::GUARD, ['driver' => 'jwt', 'provider' => 'normalised']);
        $config->set('auth.providers.normalised', ['driver' => 'model', 'model' => NormalisedEmailIdentity::class]);
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * A provider over the identity whose hasher wants bcrypt cost 5.
     *
     * @return \SineMacula\Laravel\Authentication\Providers\ModelProvider
     */
    private function provider(): ModelProvider
    {
        return new ModelProvider(new BcryptHasher(['rounds' => 5]), NormalisedEmailIdentity::class);
    }

    /**
     * Seed the identity with its password hashed at the given bcrypt cost.
     *
     * @param  int  $cost
     * @return \Tests\Integration\Fixtures\NormalisedEmailIdentity
     */
    private function seedIdentity(int $cost): NormalisedEmailIdentity
    {
        return NormalisedEmailIdentity::query()->create([
            'email'    => 'Signer@Example.test',
            'name'     => 'Signer',
            'password' => (new BcryptHasher(['rounds' => $cost]))->make(self::PASSWORD),
        ]);
    }
}
