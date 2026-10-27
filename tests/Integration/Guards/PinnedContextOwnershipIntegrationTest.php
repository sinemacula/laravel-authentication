<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Illuminate\Auth\Events\Failed;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthManager;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\Concerns\InteractsWithDevices;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\CollectionMembershipResolver;
use Tests\Integration\Fixtures\InverseRelationMembershipResolver;
use Tests\Integration\Fixtures\UnscopedMembershipResolver;
use Tests\TestCase;
use Tests\Unit\Stubs\Stub3dPrincipal;
use Tests\Unit\Stubs\StubDevice;

/**
 * A principal or device pinned on `attempt()`, as an endpoint might load it
 * from request input, is bound only when it belongs to the identity whose
 * credentials were checked: another member's membership or device, or a model
 * of another class that shares an identifier, fails the attempt, even when the
 * guard's resolver does not scope its hinted lookup to the identity.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AbstractGuard::class)]
final class PinnedContextOwnershipIntegrationTest extends TestCase
{
    use InteractsWithDevices;

    /** @var string */
    private const string PASSWORD = 'correct horse battery staple';

    /**
     * Create the tenant, member, and membership tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Schema::create('activatable_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('name');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
            $blueprint->softDeletes();
        });

        Schema::create('activatable_tenant_members', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        Schema::create('activatable_tenant_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id');
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the fixture tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('activatable_tenant_memberships');
        Schema::dropIfExists('activatable_tenant_members');
        Schema::dropIfExists('activatable_tenants');

        parent::tearDown();
    }

    /**
     * The member's own membership and live device are bound.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOwnMembershipAndDeviceAreBound(): void
    {
        [$member, $membership, $device] = $this->seedMember('own@example.test');

        $guard = $this->freshGuard();

        self::assertTrue($guard->attempt($this->credentials($member), $membership, $device));
        self::assertSame($membership->getKey(), $guard->principal()?->getPrincipalIdentifier());
        self::assertSame($device->getKey(), $guard->device()?->getDeviceIdentifier());
    }

    /**
     * Another member's membership fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherMembersMembershipFailsTheAttempt(): void
    {
        [$member]            = $this->seedMember('first@example.test');
        [, $otherMembership] = $this->seedMember('second@example.test');

        $guard = $this->freshGuard();

        self::assertFalse($guard->attempt($this->credentials($member), $otherMembership));
        self::assertFalse($guard->hasUser());
    }

    /**
     * Another member's membership fails the attempt even on a guard whose
     * resolver finds a hinted membership by key alone, without scoping it to
     * the identity, while the member's own membership is still bound there.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherMembersMembershipFailsEvenWhenTheResolverIsNotScoped(): void
    {
        [$member, $membership] = $this->seedMember('first@example.test');
        [, $otherMembership]   = $this->seedMember('second@example.test');

        $guard = $this->freshGuard('unscoped');

        self::assertFalse($guard->attempt($this->credentials($member), $otherMembership));
        self::assertFalse($guard->hasUser());

        $guard = $this->freshGuard('unscoped');

        self::assertTrue($guard->attempt($this->credentials($member), $membership));
        self::assertSame($membership->getKey(), $guard->principal()?->getPrincipalIdentifier());
    }

    /**
     * Another member's membership fails the attempt even on a guard whose
     * resolver finds a hinted membership by key alone and sets the identity as
     * its owner relation: the owner is read from the membership's stored key,
     * not from that relation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherMembersMembershipFailsEvenWhenTheResolverSetsTheInverseRelation(): void
    {
        [$member, $membership] = $this->seedMember('first@example.test');
        [, $otherMembership]   = $this->seedMember('second@example.test');

        $guard = $this->freshGuard('inverse');

        self::assertFalse($guard->attempt($this->credentials($member), $otherMembership));
        self::assertFalse($guard->hasUser());

        $guard = $this->freshGuard('inverse');

        self::assertTrue($guard->attempt($this->credentials($member), $membership));
        self::assertSame($membership->getKey(), $guard->principal()?->getPrincipalIdentifier());
    }

    /**
     * Another member's membership whose owner has been deleted fails the
     * attempt, with `Failed` dispatched, on a guard whose resolver is not
     * scoped: an owner that cannot be loaded is not the identity signing in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMembershipWhoseOwnerIsDeletedFailsTheAttempt(): void
    {
        [$member]                        = $this->seedMember('first@example.test');
        [$otherMember, $otherMembership] = $this->seedMember('second@example.test');

        $otherMember->delete();

        $failed = [];

        Event::listen(Failed::class, static function (Failed $event) use (&$failed): void {
            $failed[] = $event->user;
        });

        $guard = $this->freshGuard('unscoped');

        self::assertFalse($guard->attempt($this->credentials($member), $otherMembership));
        self::assertFalse($guard->hasUser());
        self::assertCount(1, $failed);
        self::assertTrue($member->is($failed[0]));
    }

    /**
     * The member's own membership, hydrated as one of several rows with lazy
     * loading prevented (Eloquent's strict mode), is still bound: the owner the
     * package re-reads from the stored key is not a lazy-loading violation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOwnMembershipHydratedWithLazyLoadingPreventedIsBound(): void
    {
        [$member, $membership] = $this->seedMember('strict@example.test');

        $second = new ActivatableTenantMembership;
        $second->forceFill(['identity_id' => $member->getKey(), 'tenant_id' => $membership->tenant_id])->save();

        Model::preventLazyLoading();

        try {
            $guard = $this->freshGuard('collection');

            self::assertTrue($guard->attempt($this->credentials($member), $second));
            self::assertSame($second->getKey(), $guard->principal()?->getPrincipalIdentifier());
        } finally {
            Model::preventLazyLoading(false);
        }
    }

    /**
     * A principal of another class whose identifier equals the member's own
     * membership identifier fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testPrincipalOfAnotherClassWithTheSameIdentifierFailsTheAttempt(): void
    {
        [$member, $membership] = $this->seedMember('collide@example.test');

        $impostor = new Stub3dPrincipal;
        $impostor->forceFill(['id' => $membership->getKey()]);

        $guard = $this->freshGuard();

        self::assertFalse($guard->attempt($this->credentials($member), $impostor));
        self::assertFalse($guard->hasUser());
    }

    /**
     * Another member's device fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnotherMembersDeviceFailsTheAttempt(): void
    {
        [$member]          = $this->seedMember('first@example.test');
        [, , $otherDevice] = $this->seedMember('second@example.test');

        $guard = $this->freshGuard();

        self::assertFalse($guard->attempt($this->credentials($member), null, $otherDevice));
        self::assertFalse($guard->hasUser());
    }

    /**
     * A device of another model class whose identifier equals the member's own
     * device identifier fails the attempt.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testDeviceOfAnotherClassWithTheSameIdentifierFailsTheAttempt(): void
    {
        [$member, , $device] = $this->seedMember('collide@example.test');

        $impostor = new StubDevice;
        $impostor->forceFill(['id' => $device->getKey()]);

        $guard = $this->freshGuard();

        self::assertFalse($guard->attempt($this->credentials($member), null, $impostor));
        self::assertFalse($guard->hasUser());
    }

    /**
     * The member's own device fails the attempt once revoked, even when the
     * caller's instance predates the revocation.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokedDeviceFailsTheAttempt(): void
    {
        [$member, , $device] = $this->seedMember('revoked@example.test');

        Device::query()->whereKey($device->getKey())->update(['revoked_at' => Carbon::now()]);

        $guard = $this->freshGuard();

        self::assertFalse($guard->attempt($this->credentials($member), null, $device));
        self::assertFalse($guard->hasUser());
    }

    /**
     * Configure the JWT guard against the member provider.
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

        $config->set('auth.guards.api', [
            'driver'   => 'jwt',
            'provider' => 'members',
        ]);

        $config->set('auth.guards.unscoped', [
            'driver'             => 'jwt',
            'provider'           => 'members',
            'principal_resolver' => UnscopedMembershipResolver::class,
        ]);

        $config->set('auth.guards.collection', [
            'driver'             => 'jwt',
            'provider'           => 'members',
            'principal_resolver' => CollectionMembershipResolver::class,
        ]);

        $config->set('auth.guards.inverse', [
            'driver'             => 'jwt',
            'provider'           => 'members',
            'principal_resolver' => InverseRelationMembershipResolver::class,
        ]);

        $config->set('auth.providers.members', [
            'driver' => 'model',
            'model'  => ActivatableTenantMember::class,
        ]);

        // Failed attempts wait out the timebox; keep it short.
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist a member with a membership in its own tenant and a live device.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @param  string  $email
     * @return array{0: \Tests\Integration\Fixtures\ActivatableTenantMember, 1: \Tests\Integration\Fixtures\ActivatableTenantMembership, 2: \SineMacula\Laravel\Authentication\Models\Device}
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    private function seedMember(string $email): array
    {
        $tenant = new ActivatableTenant;
        $tenant->forceFill(['name' => $email, 'is_active' => true])->save();

        $member = new ActivatableTenantMember;
        $member->forceFill(['email' => $email, 'password' => app(Hasher::class)->make(self::PASSWORD)])->save();

        $membership = new ActivatableTenantMembership;
        $membership->forceFill(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()])->save();

        $device = new Device;
        $device->forceFill([
            ...self::liveSession(),
            'authenticatable_type' => ActivatableTenantMember::class,
            'authenticatable_id'   => (string) $member->getKey(), // @phpstan-ignore cast.string
        ])->save();

        return [$member, $membership, $device];
    }

    /**
     * Build the member's correct credentials.
     *
     * @param  \Tests\Integration\Fixtures\ActivatableTenantMember  $member
     * @return array<string, mixed>
     */
    private function credentials(ActivatableTenantMember $member): array
    {
        return ['email' => $member->email, 'password' => self::PASSWORD];
    }

    /**
     * Resolve a fresh JWT guard (`api` by default) against a fresh request.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function freshGuard(string $name = 'api'): JwtGuard
    {
        app()->instance('request', Request::create('/sign-in', 'POST'));

        $manager = app('auth');

        assert($manager instanceof AuthManager);

        $manager->forgetGuards();

        $guard = $manager->guard($name);

        assert($guard instanceof JwtGuard);

        return $guard;
    }
}
