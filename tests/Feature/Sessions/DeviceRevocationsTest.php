<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Logout;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Devices\IdentityDevices;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Guards\AbstractGuard;
use SineMacula\Laravel\Authentication\IdentifierChanges\PendingChanges;
use SineMacula\Laravel\Authentication\Models\PendingSignIn;
use SineMacula\Laravel\Authentication\Sessions\Concerns\EndsSessions;
use SineMacula\Laravel\Authentication\Sessions\DeviceRevocations;
use SineMacula\Laravel\Authentication\Sessions\RevocationScope;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\AccessOnlyIdentity;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\CutoffIdentity;
use Tests\Integration\Fixtures\ForeignModelDevicesIdentity;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;
use Tests\Unit\Stubs\PlainDeviceFixture;

/**
 * Feature tests of the session service's sign-out and revocation methods: what
 * each revokes, what it leaves alone, what it reports, and the cutoff and
 * pending sign-ins a bulk revocation ends with the devices.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(DeviceRevocations::class)]
#[CoversClass(RevocationScope::class)]
#[CoversClass(IdentityDevices::class)]
#[CoversClass(AbstractGuard::class)]
#[CoversClass(SessionRevocations::class)]
#[CoversTrait(EndsSessions::class)]
final class DeviceRevocationsTest extends TestCase
{
    use InteractsWithSessions;

    /** @var string The frozen time every revocation happens at. */
    private const string NOW = '2027-01-15 10:00:00';

    /**
     * Freeze the clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        CarbonImmutable::setTestNow(CarbonImmutable::parse(self::NOW));
        Carbon::setTestNow(Carbon::parse(self::NOW));

        JWT::$timestamp = CarbonImmutable::parse(self::NOW)->getTimestamp();

        $this->createSessionTables();

        Schema::create('cutoff_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email');
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Release the clock and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();
        Carbon::setTestNow();

        JWT::$timestamp = null;

        Schema::dropIfExists('cutoff_identities');

        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * Signing out a guest request does nothing and reports nothing.
     *
     * @return void
     */
    public function testSigningOutAGuestDoesNothing(): void
    {
        $this->recordEvents([DeviceRevoked::class, Logout::class]);

        self::assertFalse($this->sessions()->signOut());
        self::assertSame([], $this->recorded);
    }

    /**
     * A session without a persisted device is only forgotten: `Logout` fires,
     * nothing is revoked, and the guard stays signed out for the rest of the
     * request even though the request carries a credential.
     *
     * @return void
     */
    public function testASessionWithoutAPersistedDeviceIsOnlyForgotten(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn();
        $guard    = $this->freshGuard();

        $guard->setRequest(Request::create('/', 'GET', server: ['HTTP_AUTHORIZATION' => 'Bearer ' . $session->tokens->accessToken]));
        $guard->login($identity, $identity, new PlainDeviceFixture('plain-device'));

        $this->recordEvents([DeviceRevoked::class, Logout::class]);

        self::assertFalse(self::sessionsOf($guard)->signOut());
        self::assertSame([Logout::class], $this->recordedClasses());
        self::assertTrue($guard->guest());
        self::assertNull($guard->device());
        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
    }

    /**
     * Signing out revokes the bound device once: a second sign-out on a request
     * bound to the same, already revoked device reports nothing more.
     *
     * @return void
     */
    public function testSigningOutRevokesTheBoundDeviceOnce(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn();

        $guard = $this->freshGuard();
        $guard->login($identity, $identity, $session->device);

        $this->recordEvents([DeviceRevoked::class]);

        self::assertTrue(self::sessionsOf($guard)->signOut());

        $guard->login($identity, $identity, $session->device);

        self::assertFalse(self::sessionsOf($guard)->signOut());
        self::assertCount(1, $this->recorded);
        self::assertSame(self::NOW, DB::table('devices')->value('revoked_at'));
    }

    /**
     * Signing out reports the tenant the bound principal acts within, and none
     * when that tenant can no longer be loaded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningOutReportsTheBoundTenantWhenItLoads(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $loaded = $membership;

        $this->recordEvents([DeviceRevoked::class]);

        foreach ([true, false] as $loads) {

            $session = $this->signIn('members', 'member@example.test');
            $guard   = $this->freshGuard('members');

            if (!$loads) {
                $tenant->delete();
                $membership = ActivatableTenantMembership::query()->findOrFail($membership->getKey());
            }

            $guard->login($member, $membership, $session->device);

            self::assertTrue(self::sessionsOf($guard)->signOut());
        }

        [$loading, $unloadable] = $this->recorded;

        self::assertInstanceOf(DeviceRevoked::class, $loading);
        self::assertInstanceOf(DeviceRevoked::class, $unloadable);
        self::assertSame(IdentifierCoercion::stringify($tenant->getKey()), $loading->context->tenantId);
        self::assertSame($loaded, $loading->context->principal);
        self::assertNull($unloadable->context->tenant);
    }

    /**
     * IdentityDevices is a static utility; instantiation is disallowed through
     * the private constructor. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testIdentityDevicesCannotBeInstantiated(): void
    {
        $reflection  = new \ReflectionClass(IdentityDevices::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);
    }

    /**
     * A bound device that is not an Eloquent model has nothing to revoke: the
     * session is only forgotten, and the device is never asked anything.
     *
     * @return void
     */
    public function testABoundDeviceThatIsNotAModelIsOnlyForgotten(): void
    {
        $identity = $this->seedIdentity();
        $device   = \Mockery::mock(EloquentDevice::class);
        $guard    = $this->freshGuard();

        $device->shouldReceive('getSignInMethod')->andReturn('password');
        $device->shouldReceive('getDeviceIdentifier')->andReturn('mocked-device');
        $device->shouldNotReceive('getGuard');

        $guard->login($identity, $identity, $device);

        self::assertFalse(self::sessionsOf($guard)->signOut());
        self::assertTrue($guard->guest());
    }

    /**
     * Signing out everywhere revokes the request's own device too unless asked
     * to keep it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningOutEverywhereRevokesTheCurrentDeviceByDefault(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn();
        $guard    = $this->freshGuard();

        $guard->login($identity, $identity, $session->device);

        self::assertSame(1, self::sessionsOf($guard)->signOutEverywhere());
        self::assertSame(self::NOW, self::revokedAt($session));
    }

    /**
     * An identity whose key is unknown, as an unsaved model's, records no
     * pending sign-ins, so none is deleted for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWithoutAKeyEndsNoPendingSignIns(): void
    {
        $this->seedIdentity();

        $pending = $this->pendingSignIn();

        self::assertSame(0, $this->sessions()->revokeDevices(new IntegrationIdentity, RevocationReason::REVOKED));
        self::assertTrue(PendingSignIn::query()->whereKey(explode('.', $pending, 2)[0])->exists());
    }

    /**
     * A scope picks devices and pending sign-ins by type as well as by
     * identifier: another type's rows with the same identifier are left alone.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAScopeMatchesTheTypeAsWellAsTheIdentifier(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn();

        DB::table('devices')->update(['authenticatable_type' => 'another_type', 'principal_type' => 'another_type']);
        DB::table('pending_sign_ins')->insert($this->pendingRow('another_type', IdentifierCoercion::stringify($identity->getKey()) ?? ''));

        $this->sessions()->revokeDevices($identity, RevocationReason::REVOKED);
        $this->sessions()->revokePrincipalDevices($identity, RevocationReason::REVOKED);

        self::assertNull(self::revokedAt($session));
        self::assertSame(1, DB::table('pending_sign_ins')->count());
    }

    /**
     * Signing out everywhere on a guest request revokes nothing.
     *
     * @return void
     */
    public function testSigningOutEverywhereAsAGuestRevokesNothing(): void
    {
        $this->seedIdentity();
        $this->signIn();

        self::assertSame(0, $this->sessions()->signOutEverywhere());
        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());
    }

    /**
     * Revoking an identity's devices covers every guard, skips the excepted
     * device, leaves other identities' devices alone, ends the identity's
     * pending sign-ins, and reports each device and then the scope.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokingAnIdentitysDevicesEndsEverySessionButTheExcepted(): void
    {
        $identity = $this->seedIdentity();

        $this->seedIdentity('grace@example.test');

        $kept    = $this->signIn();
        $revoked = $this->signIn('admin');
        $theirs  = $this->signIn('api', 'grace@example.test');
        $pending = $this->pendingSignIn();
        $mine    = $this->pendingSignIn('grace@example.test');

        $this->recordEvents([DeviceRevoked::class, SignedOutEverywhere::class]);

        self::assertSame(1, $this->sessions('api')->revokeDevices($identity, RevocationReason::PASSWORD_CHANGED, $kept->device));

        self::assertSame([DeviceRevoked::class, SignedOutEverywhere::class], $this->recordedClasses());

        $device = $this->recordedEvent(DeviceRevoked::class);

        self::assertSame('admin', $device->context->guard);
        self::assertSame(self::idOf($revoked), $device->context->deviceId);
        self::assertSame($identity, $device->context->identity);
        self::assertNull($device->context->principal);
        self::assertSame($identity->getMorphClass(), $device->context->principalMorphClass);
        self::assertSame(IdentifierCoercion::stringify($identity->getKey()), $device->context->principalId);
        self::assertSame(RevocationReason::PASSWORD_CHANGED, $device->reason);

        $scope = $this->recordedEvent(SignedOutEverywhere::class);

        self::assertSame('api', $scope->context->guard);
        self::assertSame($identity, $scope->context->identity);
        self::assertSame(self::idOf($kept), $scope->context->deviceId);
        self::assertSame(1, $scope->revoked);
        self::assertNull($scope->tokensValidAfter);

        self::assertNull(self::revokedAt($kept));
        self::assertNull(self::revokedAt($theirs));
        self::assertSame(self::NOW, self::revokedAt($revoked));
        self::assertFalse(PendingSignIn::query()->whereKey(explode('.', $pending, 2)[0])->exists());
        self::assertTrue(PendingSignIn::query()->whereKey(explode('.', $mine, 2)[0])->exists());
        self::assertSame(FailureReason::PENDING_INVALID, $this->sessions()->complete($pending)->reason);
        self::assertTrue($this->sessions()->complete($mine)->isSignedIn());
    }

    /**
     * An excepted device of another model is not a device of the scope, so
     * nothing is kept for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnExceptedDeviceOfAnotherModelKeepsNothing(): void
    {
        $identity = $this->seedIdentity();

        $this->signIn();

        self::assertSame(1, $this->sessions()->revokeDevices($identity, RevocationReason::REVOKED, new PlainDeviceFixture('plain-device')));
    }

    /**
     * A revocation of several scopes counts every scope's revoked devices, and
     * reports each scope with its own count.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSeveralScopesCountEveryScopesDevices(): void
    {
        [, $first, $tenant] = $this->seedMember();
        [, $second]         = $this->seedMember('other@example.test', $tenant);

        $this->signIn('members', 'member@example.test');
        $this->signIn('members', 'member@example.test');
        $this->signIn('members', 'other@example.test');

        $this->recordEvents([SignedOutEverywhere::class]);

        self::assertSame(3, $this->sessions('members')->tenantDeactivated($tenant, [$first, $second]));
        self::assertSame([2, 1], array_map(static fn (object $event): int => $event instanceof SignedOutEverywhere ? $event->revoked : -1, $this->recorded));
    }

    /**
     * A bulk revocation deletes the pending identifier changes its identity
     * scopes name, in the same transaction as their devices, and no other: a
     * principal's scope names none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABulkRevocationDeletesThePendingChangesItsScopesName(): void
    {
        $identity = $this->seedIdentity();
        $other    = $this->seedIdentity('grace@example.test');
        $keys     = [PendingChanges::key($identity, 'email'), PendingChanges::key($identity, 'phone'), PendingChanges::key($other, 'email')];

        foreach ($keys as $index => $key) {
            DB::table('identifier_changes')->insert([
                'id'           => $key,
                'guard'        => 'api',
                'type'         => 'email',
                'previous'     => null,
                'identifier'   => "new{$index}@example.test",
                'request_id'   => "0195f4a2-7b1c-4000-8000-00000000000{$index}",
                'requested_at' => self::NOW,
                'expires_at'   => self::NOW,
            ]);
        }

        $revocations = new DeviceRevocations(app('db'), static fn (): mixed => null);
        $none        = static function (): void {};

        $revocations->revokeScopes([RevocationScope::principal($identity)], RevocationReason::REVOKED, null, CarbonImmutable::now(), $none, $none);

        self::assertSame(3, DB::table('identifier_changes')->count());

        $revocations->revokeScopes([RevocationScope::identity($identity, ['email', 'phone'])], RevocationReason::REVOKED, null, CarbonImmutable::now(), $none, $none);

        self::assertSame([$keys[2]], DB::table('identifier_changes')->pluck('id')->all());
    }

    /**
     * A bulk revocation with nothing left to revoke is still reported, with a
     * count of none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABulkRevocationOfNothingIsStillReported(): void
    {
        $identity = $this->seedIdentity();

        $this->recordEvents([DeviceRevoked::class, SignedOutEverywhere::class]);

        self::assertSame(0, $this->sessions()->revokeDevices($identity, RevocationReason::REVOKED));
        self::assertSame([SignedOutEverywhere::class], $this->recordedClasses());
        self::assertSame(0, $this->recordedEvent(SignedOutEverywhere::class)->revoked);
    }

    /**
     * An identity that cannot hold devices cannot hold a pending sign-in either
     * (no session starts for it), so its revocation leaves both tables alone, a
     * row recorded for it by hand included, and is still reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentityWithoutDevicesLeavesThePackagesTablesAlone(): void
    {
        Schema::create('access_only_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email');
            $blueprint->timestamps();
        });

        $identity = new AccessOnlyIdentity;
        $identity->forceFill(['email' => 'ada@example.test'])->save();

        DB::table('pending_sign_ins')->insert($this->pendingRow($identity->getMorphClass(), IdentifierCoercion::stringify($identity->getKey()) ?? ''));

        $this->recordEvents([SignedOutEverywhere::class]);

        self::assertSame(0, $this->sessions()->revokeDevices($identity, RevocationReason::IDENTITY_DEACTIVATED));
        self::assertSame(1, DB::table('pending_sign_ins')->count());
        self::assertCount(1, $this->recorded);

        Schema::drop('access_only_identities');
    }

    /**
     * An identity that holds no devices has none to revoke one of.
     *
     * @return void
     */
    public function testAnIdentityWithoutDevicesHasNoneToRevoke(): void
    {
        self::assertFalse($this->sessions()->revokeDevice(new AccessOnlyIdentity, '0190e1a4-0000-7000-8000-000000000000', RevocationReason::REVOKED));
    }

    /**
     * A misconfigured `devices()` relation over a model that is not a device is
     * refused before anything is written.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRefusesADevicesRelationOverAnotherModel(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('The devices() relation of ' . ForeignModelDevicesIdentity::class . ' must query a model that implements');

        $this->sessions()->revokeDevices(new ForeignModelDevicesIdentity, RevocationReason::REVOKED);
    }

    /**
     * Revoking a principal's devices revokes only the sessions acting as it, of
     * every identity's devices recording it, and ends the pending sign-ins that
     * would act as it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testRevokingAPrincipalsDevicesEndsOnlyItsSessions(): void
    {
        [, $membership, $tenant] = $this->seedMember();
        [, $otherMembership]     = $this->seedMember('other@example.test', $tenant);

        $mine   = $this->signIn('members', 'member@example.test');
        $theirs = $this->signIn('members', 'other@example.test');

        $this->recordEvents([DeviceRevoked::class, SignedOutEverywhere::class]);

        self::assertSame(1, $this->sessions('members')->revokePrincipalDevices($membership, RevocationReason::PRINCIPAL_DEACTIVATED));

        $scope = $this->recordedEvent(SignedOutEverywhere::class);

        self::assertSame($membership, $scope->context->principal);
        self::assertInstanceOf(ActivatableTenantMember::class, $scope->context->identity);
        self::assertSame(IdentifierCoercion::stringify($membership->identity_id), $scope->context->identityId);
        self::assertSame($membership, $this->recordedEvent(DeviceRevoked::class)->context->principal);
        self::assertSame($scope->context->identity, $this->recordedEvent(DeviceRevoked::class)->context->identity);
        self::assertSame(self::NOW, self::revokedAt($mine));
        self::assertNull(self::revokedAt($theirs));
        self::assertSame(IdentifierCoercion::stringify($otherMembership->getKey()), DB::table('devices')->whereNull('revoked_at')->value('principal_id'));
    }

    /**
     * An unsaved principal records no sessions: nothing is revoked, and a
     * device that records no principal is not taken for it.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnUnsavedPrincipalRevokesNothing(): void
    {
        $this->seedIdentity();

        $session = $this->signIn();

        DB::table('devices')->update(['principal_type' => null, 'principal_id' => null]);

        self::assertSame(0, $this->sessions()->revokePrincipalDevices(new ActivatableTenantMembership, RevocationReason::REVOKED));
        self::assertNull(self::revokedAt($session));
    }

    /**
     * A scope that records a "tokens valid after" cutoff has it moved to the
     * revocation's second, which the event reports; a second revocation in the
     * same second moves nothing and reports none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testMovesTheScopesCutoffAndReportsIt(): void
    {
        $identity = new CutoffIdentity;
        $identity->forceFill(['email' => 'ada@example.test'])->save();
        $identity = CutoffIdentity::query()->findOrFail($identity->id);

        $this->recordEvents([SignedOutEverywhere::class]);

        $this->sessions()->revokeDevices($identity, RevocationReason::SIGNED_OUT_EVERYWHERE);
        $this->sessions()->revokeDevices($identity, RevocationReason::SIGNED_OUT_EVERYWHERE);

        self::assertSame(self::NOW, DB::table('cutoff_identities')->value('tokens_valid_after'));
        [$first, $second] = $this->recorded;

        self::assertInstanceOf(SignedOutEverywhere::class, $first);
        self::assertInstanceOf(SignedOutEverywhere::class, $second);
        self::assertSame(self::NOW, $first->tokensValidAfter?->format('Y-m-d H:i:s'));
        self::assertNull($second->tokensValidAfter);
    }

    /**
     * Register the session guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * Sign the identity with the email in on the guard.
     *
     * @param  string  $guard
     * @param  string  $email
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(string $guard = 'api', string $email = 'ada@example.test'): SignedInSession
    {
        $session = $this->sessions($guard)->signIn('password', self::credentials($email))->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Sign the identity with the email in while every sign-in needs a further
     * factor, and return the pending token.
     *
     * @param  string  $email
     * @return string
     *
     * @throws \Throwable
     */
    private function pendingSignIn(string $email = 'ada@example.test'): string
    {
        $previous = app(AdditionalFactorPolicy::class);

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

        $pending = $this->sessions()->signIn('password', self::credentials($email))->pending;

        app()->instance(AdditionalFactorPolicy::class, $previous);

        self::assertNotNull($pending);

        return $pending->token;
    }

    /**
     * A pending sign-in row for the owner.
     *
     * @param  string  $type
     * @param  string  $id
     * @return array<string, mixed>
     */
    private function pendingRow(string $type, string $id): array
    {
        return [
            'id'                   => '0190e1a4-0000-7000-8000-000000000001',
            'token_digest'         => str_repeat('a', 64),
            'purpose'              => PendingSignIn::ADDITIONAL_FACTOR,
            'guard'                => 'api',
            'sign_in_method'       => 'password',
            'authenticatable_type' => $type,
            'authenticatable_id'   => $id,
            'principal_type'       => $type,
            'principal_id'         => $id,
            'expires_at'           => '2027-01-15 10:05:00',
        ];
    }

    /**
     * The identifier of the session's device.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return string
     */
    private static function idOf(SignedInSession $session): string
    {
        return (string) IdentifierCoercion::stringify($session->device->getDeviceIdentifier());
    }

    /**
     * When the session's device was revoked, as stored.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return mixed
     */
    private static function revokedAt(SignedInSession $session): mixed
    {
        return DB::table('devices')->where('id', self::idOf($session))->value('revoked_at');
    }
}
