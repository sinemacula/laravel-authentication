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
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\Coexist3dIdentity;
use Tests\Integration\Fixtures\Coexist3dPrincipal;
use Tests\Integration\Fixtures\IntegrationIdentity;

/**
 * Query-budget and timing contracts for credential sign-in through `attempt()`:
 * the reads each outcome costs, including the pinned principal's owner re-read
 * and the pinned device lookup, the writes of the shipped attempt limits, and
 * the timebox that keeps a failed attempt as slow as an unknown identifier.
 *
 * Every attempt first reserves a slot on the identifier's and the IP address's
 * counters. The first attempt of a window finds neither counter, so each
 * reservation is an update that changes nothing and the insert that creates the
 * counter: four writes. A later attempt in the window updates the two existing
 * counters: two writes. An attempt that finds an account reserves a slot on the
 * account's counter too before its password is checked (two writes on a fresh
 * window, one later) and gives it back when the password matches (one more). A
 * successful attempt then gives the first two slots back: two more. A failed
 * attempt keeps them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
final class JwtGuardAttemptBudgetTest extends PerformanceContractTestCase
{
    use InteractsWithDevices;

    /** @var string Shared plaintext password for the seeded fixtures. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var string Guard over the 2D identity that owns devices. */
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
     * A sign-in whose stored hash the hasher no longer produces (a lower bcrypt
     * cost) costs one write on top of its limits: the rehashed password. The
     * hash is made before the cost goes up, so the stored one is outdated. The
     * next sign-in finds the counters and the new hash in place.
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
     * Rows of `[credentials, active, writes]`: rejected sign-ins, whether the
     * seeded identity is active, and the writes each costs: an unknown
     * identifier reserves only the identifier's and the IP address's slots, a
     * wrong password the account's too, and an inactive identity, whose
     * password matched, gives the account's back.
     *
     * @return iterable<string, array{0: array<string, string>, 1: bool, 2: int}>
     */
    public static function provideRejectedCredentials(): iterable
    {
        yield from [
            'unknown identifier' => [['email' => 'nobody@example.test', 'password' => self::PASSWORD], true, 4],
            'wrong password'     => [['email' => 'signer@example.test', 'password' => 'wrong'], true, 6],
            'inactive identity'  => [['email' => 'signer@example.test', 'password' => self::PASSWORD], false, 7],
        ];
    }

    /**
     * A rejected sign-in reads the identity once and writes only the
     * reservations it keeps, whether the identifier is unknown, the password is
     * wrong, or the identity is inactive.
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
     * A pinned live device costs one read on top of the identity, plus the
     * first-use timestamp write besides the limits; a pinned revoked device
     * costs the same reads, writes only its reservations and the account's
     * returned slot, and fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAttemptWithPinnedDeviceUsesTwoReads(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->seedDevice($identity);

        $guard = $this->freshGuard(self::TWO_D_GUARD);

        self::assertTrue($this->assertQueryBudget(2, 10, fn (): bool => $guard->attempt($this->credentials($identity->email), null, $device)));
        self::assertSame($device->getKey(), $guard->device()?->getDeviceIdentifier());

        Device::query()->whereKey($device->getKey())->update(['revoked_at' => $this->now]);

        $guard = $this->freshGuard(self::TWO_D_GUARD);

        self::assertFalse($this->assertQueryBudget(2, 4, fn (): bool => $guard->attempt($this->credentials($identity->email), null, $device)));
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
     * Pinning another identity's principal misses the hinted lookup; the
     * resolver falls back to the identity's default principal, whose id does
     * not match the pin, so the attempt fails without any owner read and keeps
     * its reservations; the account's slot went back when the password matched.
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

        self::assertFalse($this->assertQueryBudget(3, 7, fn (): bool => $guard->attempt($this->credentials($identity->email), $foreignMember)));
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
     * A sign-in to an account stored without a password hash is rejected like a
     * wrong password: it reads the identity once, writes only the reservations
     * it keeps, the account's included, and waits out the real timebox.
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
     * A successful sign-in returns as soon as it is done instead of waiting out
     * the timebox. The fastest of a few sign-ins is compared, so one scheduler
     * pause or slow query cannot fail the contract; the early return itself is
     * pinned without timing in AbstractGuardAttemptLifecycleTest.
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
            'driver'   => 'jwt',
            'provider' => 'integration_identities',
        ]);

        $config->set('auth.guards.' . self::THREE_D_GUARD, [
            'driver'   => 'jwt',
            'provider' => 'coexist_3d_identities',
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
     * Persist a live device for the 2D identity.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private function seedDevice(IntegrationIdentity $identity): Device
    {
        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => IntegrationIdentity::class,
            'authenticatable_id'   => (string) $identity->getKey(), // @phpstan-ignore cast.string
        ])->save();

        return $device;
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
