<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Testing\ActingContext;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Feature tests for how the acting context finds what it acts on through the
 * application's guards: the package guard named or the default one, the
 * resolver's default principal, and the owner and principal a device's session
 * records, each refused with what could not be found.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ActingContext::class)]
final class ActingContextTest extends TestCase
{
    use InteractsWithSessions;

    /**
     * Create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * The guard named, or the default one, is resolved through the auth
     * manager, either package driver accepted.
     *
     * @return void
     */
    public function testTheNamedOrDefaultPackageGuardIsResolved(): void
    {
        Auth::shouldUse('admin');

        self::assertSame(Auth::guard('admin'), ActingContext::guard(null));
        self::assertSame(Auth::guard('api'), ActingContext::guard('api'));
        self::assertSame(Auth::guard('machine'), ActingContext::guard('machine'));
    }

    /**
     * A guard of another driver is refused by its name, whether it is named or
     * is the default.
     *
     * @return void
     */
    public function testAGuardOfAnotherDriverIsRefused(): void
    {
        foreach (['api' => 'web', 'web' => null] as $default => $name) {

            Auth::shouldUse($default);

            try {
                ActingContext::guard($name);
                self::fail('The session guard was accepted.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('Auth guard [web] is not a package guard (jwt or api_key), so a test cannot act on it with these helpers.', $exception->getMessage());
            }
        }
    }

    /**
     * The default principal is the resolver's, and an identity without one is
     * refused naming the guard and the identity's class.
     *
     * @return void
     */
    public function testTheDefaultPrincipalIsTheResolversOrRefused(): void
    {
        [$member, $membership] = $this->seedMember();

        $guard = ActingContext::guard('members');

        self::assertTrue($membership->is(ActingContext::defaultPrincipal($guard, $member)));

        $alone = ActivatableTenantMember::query()->create(['email' => 'alone@example.test', 'password' => 'irrelevant']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('Guard members could not resolve a default principal for identity %s;', ActivatableTenantMember::class));

        ActingContext::defaultPrincipal($guard, $alone);
    }

    /**
     * A device's session is acted on as the owner and the principal it records,
     * two- and three-dimensional alike, found afresh through the guard.
     *
     * @return void
     */
    public function testADeviceActsAsTheOwnerAndPrincipalItRecords(): void
    {
        $ada                   = $this->seedIdentity();
        [$member, $membership] = $this->seedMember();

        [$identity, $principal] = ActingContext::recordedOn(ActingContext::guard('api'), $this->device('api', 'ada@example.test'));

        self::assertInstanceOf(IntegrationIdentity::class, $identity);
        self::assertTrue($ada->is($identity));
        self::assertSame($identity, $principal);

        [$identity, $principal] = ActingContext::recordedOn(ActingContext::guard('members'), $this->device('members', 'member@example.test'));

        self::assertInstanceOf(ActivatableTenantMember::class, $identity);
        self::assertTrue($member->is($identity));
        self::assertInstanceOf(ActivatableTenantMembership::class, $principal);
        self::assertTrue($membership->is($principal));
    }

    /**
     * A device that records no principal acts as the owner's default one.
     *
     * @return void
     */
    public function testADeviceRecordingNoPrincipalActsAsTheDefault(): void
    {
        [, $membership] = $this->seedMember();

        $device = $this->device('members', 'member@example.test');

        $device->forceFill(['principal_id' => null]);

        [, $principal] = ActingContext::recordedOn(ActingContext::guard('members'), $device);

        self::assertTrue($membership->is($principal));
    }

    /**
     * Rows of `[guard, change to the device, message]`: devices whose owner or
     * principal cannot be found through the guard.
     *
     * @return iterable<string, array{0: string, 1: array<string, mixed>, 2: string}>
     */
    public static function provideUnfoundSessions(): iterable
    {
        $owner     = 'Device [%s] has no owner the provider of guard [api] finds.';
        $principal = 'The resolver of guard [members] does not resolve the principal device [%s] records.';

        yield from [
            'no owner key'                         => ['api', ['authenticatable_id' => null], $owner],
            'an owner the provider does not find'  => ['api', ['authenticatable_id' => '999'], $owner],
            'an owner of another type'             => ['api', ['authenticatable_type' => ActivatableTenantMember::class], $owner],
            'a principal the resolver cannot find' => ['members', ['principal_id' => '999'], $principal],
            'a principal of another type'          => ['members', ['principal_type' => IntegrationIdentity::class], $principal],
        ];
    }

    /**
     * A device whose owner the guard's provider does not find, or whose
     * principal its resolver does not resolve as recorded, is refused.
     *
     * @param  string  $guard
     * @param  array<string, mixed>  $change
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideUnfoundSessions')]
    public function testADeviceWhoseSessionCannotBeFoundIsRefused(string $guard, array $change, string $message): void
    {
        $this->seedIdentity();
        $this->seedMember();

        $device = $this->device($guard, $guard === 'api' ? 'ada@example.test' : 'member@example.test');

        $device->forceFill($change);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf($message, $device->getKey()));

        ActingContext::recordedOn(ActingContext::guard($guard), $device);
    }

    /**
     * Configure the session guards and an API key guard.
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

        $config = $app->make(ConfigRepository::class);

        self::configureSessionGuards($config);

        $config->set('auth.guards.machine', ['driver' => 'api_key', 'provider' => 'identities']);
    }

    /**
     * Sign the identity with the email in on the guard and return its device,
     * read afresh.
     *
     * @param  string  $guard
     * @param  string  $email
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private function device(string $guard, string $email): Device
    {
        $device = $this->sessions($guard)->signIn('password', self::credentials($email))->session?->device;

        self::assertInstanceOf(Device::class, $device);

        return Device::query()->whereKey($device->getKey())->firstOrFail();
    }
}
