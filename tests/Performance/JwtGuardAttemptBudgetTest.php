<?php

declare(strict_types = 1);

namespace Tests\Performance;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Models\Session;
use Tests\Concerns\InteractsWithSessionRecords;
use Tests\Integration\Fixtures\Coexist3dIdentity;
use Tests\Integration\Fixtures\Coexist3dPrincipal;
use Tests\Integration\Fixtures\IntegrationIdentity;

/**
 * Query-budget and timing contracts for credential sign-in through `attempt()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
final class JwtGuardAttemptBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithSessionRecords;

    /** @var string Shared plaintext password for the seeded fixtures. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var string Guard over the 2D identity that owns sessions. */
    private const string TWO_D_GUARD = 'api';

    /** @var string Guard over the 3D identity and its principals. */
    private const string THREE_D_GUARD = 'api_3d';

    /** @var int Timebox for the timing contracts, in microseconds. */
    private const int TIMEBOX_MICROSECONDS = 200000;

    /** @var int Successful sign-ins timed against the timebox. */
    private const int SUCCESSFUL_TIMING_SAMPLES = 3;

    /**
     * Provision the fixture tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('integration_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('coexist_3d_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });

        Schema::create('coexist_3d_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Release the fixture tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('coexist_3d_principals');
        Schema::dropIfExists('coexist_3d_identities');
        Schema::dropIfExists('integration_identities');

        parent::tearDown();
    }

    /**
     * A 2D sign-in reads the identity once, and writes only its limits: the
     * three reservations of a fresh window and their release.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSuccessfulAttemptReadsTheIdentityOnceAndWritesOnlyItsLimits(): void
    {
        $identity = $this->seedIdentity();
        $guard    = $this->freshGuard(self::TWO_D_GUARD);

        self::assertTrue($this->assertQueryBudget(1, 9, fn (): bool => $guard->attempt($this->credentials($identity->email))));
    }

    /**
     * A sign-in whose stored hash is outdated writes the rehash on top of its
     * limits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSuccessfulAttemptWithAnOutdatedHashWritesTheRehashOnce(): void
    {
        $identity = $this->seedIdentity();

        config()->set('hashing.bcrypt.rounds', 5);
        app()->forgetInstance('hash');
        app()->forgetInstance('hash.driver');

        $guard = $this->freshGuard(self::TWO_D_GUARD);

        self::assertTrue($this->assertQueryBudget(1, 10, fn (): bool => $guard->attempt($this->credentials($identity->email))));

        $guard = $this->freshGuard(self::TWO_D_GUARD);

        self::assertTrue($this->assertQueryBudget(1, 6, fn (): bool => $guard->attempt($this->credentials($identity->email))));
    }

    /**
     * Rows of `[credentials, active, writes]`: rejected sign-ins and the writes
     * each keeps.
     *
     * @return iterable<string, array{0: array<string, string>, 1: bool, 2: int}>
     */
    public static function provideRejectedCredentials(): iterable
    {
        yield from [
            'unknown identifier' => [['email' => 'nobody@example.test', 'password' => self::PASSWORD], true, 4],
            'wrong password'     => [['email' => 'signer@example.test', 'password' => 'wrong'], true, 6],
            'inactive identity'  => [['email' => 'signer@example.test', 'password' => self::PASSWORD], false, 6],
        ];
    }

    /**
     * A rejected sign-in reads the identity once and writes only the
     * reservations it keeps.
     *
     * @param  array<string, string>  $credentials
     * @param  bool  $active
     * @param  int  $writes
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRejectedCredentials')]
    public function testRejectedAttemptReadsOnceAndWritesOnlyItsLimits(array $credentials, bool $active, int $writes): void
    {
        $this->seedIdentity($active);

        $guard = $this->freshGuard(self::TWO_D_GUARD);

        self::assertFalse($this->assertQueryBudget(1, $writes, static fn (): bool => $guard->attempt($credentials)));
        self::assertFalse($guard->hasUser());
    }

    /**
     * A guard with no `application` block refuses a sign-in before any query.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptOnAGuardThatAllowsNothingCostsNoQuery(): void
    {
        $identity = $this->seedIdentity();

        config()->set('auth.guards.' . self::TWO_D_GUARD, ['driver' => 'jwt', 'provider' => 'integration_identities']);

        $guard = $this->freshGuard(self::TWO_D_GUARD);

        self::assertFalse($this->assertQueryBudget(0, 0, fn (): bool => $guard->attempt($this->credentials($identity->email))));
        self::assertFalse($guard->hasUser());
    }

    /**
     * A pinned session costs one more read; a live one also writes its first
     * use.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptWithPinnedSessionUsesTwoReads(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->seedSession($identity);

        $guard = $this->freshGuard(self::TWO_D_GUARD);

        self::assertTrue($this->assertQueryBudget(2, 10, fn (): bool => $guard->attempt($this->credentials($identity->email), null, $session)));
        self::assertSame($session->getKey(), $guard->session()?->getSessionIdentifier());

        Session::query()->whereKey($session->getKey())->update(['revoked_at' => $this->now]);

        $guard = $this->freshGuard(self::TWO_D_GUARD);

        self::assertFalse($this->assertQueryBudget(2, 3, fn (): bool => $guard->attempt($this->credentials($identity->email), null, $session)));
    }

    /**
     * A 3D sign-in without a pin reads the identity and its default principal,
     * and writes only its limits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testThreeDimensionalAttemptReadsTwiceAndWritesOnlyItsLimits(): void
    {
        [$identity] = $this->seedThreeDimensionalIdentity();

        $guard = $this->freshGuard(self::THREE_D_GUARD);

        self::assertTrue($this->assertQueryBudget(2, 9, fn (): bool => $guard->attempt($this->credentials($identity->email))));
    }

    /**
     * A pinned principal costs the hinted lookup plus the deliberate re-read of
     * its owner from the stored key, and writes only its limits.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptWithPinnedPrincipalReadsThreeTimesAndWritesOnlyItsLimits(): void
    {
        [$identity, $principal] = $this->seedThreeDimensionalIdentity();

        $guard = $this->freshGuard(self::THREE_D_GUARD);

        self::assertTrue($this->assertQueryBudget(3, 9, fn (): bool => $guard->attempt($this->credentials($identity->email), $principal)));
        self::assertSame($principal->getKey(), $guard->principal()?->getPrincipalIdentifier());
    }

    /**
     * Pinning another identity's principal fails without an owner read and
     * keeps its reservations.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptWithAnotherIdentitysPrincipalReadsThreeTimesAndWritesOnlyItsLimits(): void
    {
        [$identity]        = $this->seedThreeDimensionalIdentity();
        [, $foreignMember] = $this->seedThreeDimensionalIdentity('foreign@example.test');

        $guard = $this->freshGuard(self::THREE_D_GUARD);

        self::assertFalse($this->assertQueryBudget(3, 6, fn (): bool => $guard->attempt($this->credentials($identity->email), $foreignMember)));
        self::assertFalse($guard->hasUser());
    }

    /**
     * Rows of `[credentials]`: sign-ins that fail, with and without a known
     * identifier.
     *
     * @return iterable<string, array{0: array<string, string>}>
     */
    public static function provideFailedCredentials(): iterable
    {
        yield from [
            'unknown identifier' => [['email' => 'nobody@example.test', 'password' => self::PASSWORD]],
            'wrong password'     => [['email' => 'signer@example.test', 'password' => 'wrong']],
        ];
    }

    /**
     * A failed sign-in waits out the real timebox whether or not the identifier
     * exists, so the response time does not reveal which accounts exist.
     *
     * @param  array<string, string>  $credentials
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideFailedCredentials')]
    public function testFailedAttemptWaitsOutTheTimebox(array $credentials): void
    {
        $this->seedIdentity();
        $this->useTimebox();

        $guard = $this->freshGuard(self::TWO_D_GUARD);

        $started = hrtime(true);

        self::assertFalse($guard->attempt($credentials));
        self::assertGreaterThanOrEqual(self::TIMEBOX_MICROSECONDS * 1000, hrtime(true) - $started);
    }

    /**
     * A sign-in to an account with no password hash is rejected like a wrong
     * password and waits out the timebox.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptOnAnAccountWithoutAPasswordReadsOnceAndWaitsOutTheTimebox(): void
    {
        $identity = $this->seedIdentity();
        $identity->forceFill(['password' => null])->save();

        $guard = $this->freshGuard(self::TWO_D_GUARD);

        self::assertFalse($this->assertQueryBudget(1, 6, fn (): bool => $guard->attempt($this->credentials($identity->email))));

        $this->useTimebox();

        $guard   = $this->freshGuard(self::TWO_D_GUARD);
        $started = hrtime(true);

        self::assertFalse($guard->attempt($this->credentials($identity->email)));
        self::assertGreaterThanOrEqual(self::TIMEBOX_MICROSECONDS * 1000, hrtime(true) - $started);
    }

    /**
     * A successful sign-in returns before the timebox.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSuccessfulAttemptReturnsBeforeTheTimebox(): void
    {
        $identity = $this->seedIdentity();

        $this->useTimebox();

        $fastest = PHP_INT_MAX;

        for ($attempt = 0; $attempt < self::SUCCESSFUL_TIMING_SAMPLES; $attempt++) {
            $guard   = $this->freshGuard(self::TWO_D_GUARD);
            $started = hrtime(true);

            self::assertTrue($guard->attempt($this->credentials($identity->email)));

            $fastest = min($fastest, hrtime(true) - $started);
        }

        self::assertLessThan(self::TIMEBOX_MICROSECONDS * 1000, $fastest);
    }

    /**
     * Configure the 2D and 3D guards, a cheap password hash, and a minimal
     * timebox for the budget contracts.
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

        $config->set('auth.guards.' . self::TWO_D_GUARD, [
            'driver'      => 'jwt',
            'provider'    => 'integration_identities',
            'application' => ['methods' => ['password']],
        ]);

        $config->set('auth.guards.' . self::THREE_D_GUARD, [
            'driver'      => 'jwt',
            'provider'    => 'coexist_3d_identities',
            'application' => ['methods' => ['password']],
        ]);

        $config->set('auth.providers.integration_identities', [
            'driver' => 'model',
            'model'  => IntegrationIdentity::class,
        ]);

        $config->set('auth.providers.coexist_3d_identities', [
            'driver' => 'model',
            'model'  => Coexist3dIdentity::class,
        ]);

        // A cheap hash keeps a successful sign-in well inside the timebox.
        $config->set('hashing.bcrypt.rounds', 4);

        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Use the real timebox length for the timing contracts.
     *
     * @return void
     */
    private function useTimebox(): void
    {
        app(ConfigRepository::class)->set('authentication.timebox.credentials_microseconds', self::TIMEBOX_MICROSECONDS);
    }

    /**
     * Sign-in credentials for the email with the correct password.
     *
     * @param  string  $email
     * @return array<string, string>
     */
    private function credentials(string $email): array
    {
        return ['email' => $email, 'password' => self::PASSWORD];
    }

    /**
     * Persist the 2D identity that signs in.
     *
     * @param  bool  $active
     * @return \Tests\Integration\Fixtures\IntegrationIdentity
     */
    private function seedIdentity(bool $active = true): IntegrationIdentity
    {
        $identity            = new IntegrationIdentity;
        $identity->email     = 'signer@example.test';
        $identity->password  = app(Hasher::class)->make(self::PASSWORD);
        $identity->is_active = $active;
        $identity->save();

        return $identity;
    }

    /**
     * Persist a live session for the 2D identity.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Models\Session
     */
    private function seedSession(IntegrationIdentity $identity): Session
    {
        $session = new Session;
        $session->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => IntegrationIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
            'principal_type'       => $identity->getMorphClass(),
            'principal_id'         => (string) $identity->getKey(), // @phpstan-ignore cast.string
        ])->save();

        return $session;
    }

    /**
     * Persist a 3D identity with one active principal.
     *
     * @formatter:off
     *
     * @param  string  $email
     * @return array{0: \Tests\Integration\Fixtures\Coexist3dIdentity, 1: \Tests\Integration\Fixtures\Coexist3dPrincipal}
     *
     * @formatter:on
     */
    private function seedThreeDimensionalIdentity(string $email = 'signer-3d@example.test'): array
    {
        $identity            = new Coexist3dIdentity;
        $identity->email     = $email;
        $identity->password  = app(Hasher::class)->make(self::PASSWORD);
        $identity->is_active = true;
        $identity->save();

        $principal              = new Coexist3dPrincipal;
        $principal->identity_id = $identity->getKey(); // @phpstan-ignore assign.propertyType
        $principal->name        = 'member';
        $principal->is_active   = true;
        $principal->save();

        return [$identity, $principal];
    }

    /**
     * Resolve a fresh guard for a sign-in request.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authentication\Guards\AbstractGuard
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    private function freshGuard(string $name): AbstractGuard
    {
        app()->instance('request', Request::create('/sign-in', 'POST'));

        return $this->freshJwtGuard($name);
    }
}
