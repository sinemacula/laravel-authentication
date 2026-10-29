<?php

declare(strict_types = 1);

namespace Tests\Integration\Events;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\AdditionalFactorPolicy;
use SineMacula\Laravel\Authentication\Events\AdditionalFactorRequired;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceCreated;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * Integration tests for the sign-in events as a queued listener receives them:
 * serialised and restored, with the identity, principal, tenant and device
 * loaded again from the database as Eloquent models (so a change made while the
 * event was queued shows), and the client, method and other values kept as they
 * were.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignedIn::class)]
#[CoversClass(DeviceCreated::class)]
#[CoversClass(AdditionalFactorRequired::class)]
#[CoversClass(AuthenticationFailed::class)]
#[CoversClass(EventContext::class)]
final class SignInEventSerialisationTest extends TestCase
{
    use InteractsWithSessions;

    /** @var \Tests\Integration\Fixtures\ActivatableTenantMember The member who signs in. */
    private ActivatableTenantMember $member;

    /** @var \Tests\Integration\Fixtures\ActivatableTenantMembership The member's membership. */
    private ActivatableTenantMembership $membership;

    /** @var \Tests\Integration\Fixtures\ActivatableTenant The tenant the membership acts within. */
    private ActivatableTenant $tenant;

    /**
     * Freeze the clocks, create the tables and seed a member.
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

        $this->createSessionTables();

        [$this->member, $this->membership, $this->tenant] = $this->seedMember();
    }

    /**
     * Release the clocks and drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropSessionTables();

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * `SignedIn` and `DeviceCreated` from a sign-in on a new device come back
     * with the member, membership, tenant and device reloaded, and the guard,
     * method and client unchanged.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSignedInAndDeviceCreatedRestoreTheirModels(): void
    {
        $this->recordEvents([SignedIn::class, DeviceCreated::class]);

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);

        $signedIn = self::roundTrip($this->recordedEvent(SignedIn::class));
        $created  = self::roundTrip($this->recordedEvent(DeviceCreated::class));

        foreach ([$signedIn, $created] as $event) {
            $this->assertRestoredModels($event->context->identity, $event->context->principal, $event->context->tenant);
            self::assertSameModel($session->device, $event->context->device);
            self::assertSame('Renamed', self::clientNameOf($event->context->device));
            self::assertSame('members', $event->context->guard);
            self::assertSame('password', $event->context->method);
            self::assertEquals(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), $event->context->client);
        }

        self::assertTrue($signedIn->deviceCreated);
    }

    /**
     * `AdditionalFactorRequired` for a sign-in that proved a device comes back
     * with that device reloaded, and with the pending sign-in's expiry.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAdditionalFactorRequiredRestoresItsModelsAndProvenDevice(): void
    {
        $first = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($first);

        self::requireAFactor();

        $this->recordEvents([AdditionalFactorRequired::class]);

        $context = new SignInContext(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), refreshToken: $first->tokens->refreshToken);
        $pending = $this->sessions('members')->signIn('password', self::credentials('member@example.test'), $context)->pending;

        self::assertNotNull($pending);

        $event = self::roundTrip($this->recordedEvent(AdditionalFactorRequired::class));

        $this->assertRestoredModels($event->context->identity, $event->context->principal, $event->context->tenant);
        self::assertNotNull($event->context->device);
        self::assertSameModel($first->device, $event->context->device);
        self::assertSame('Renamed', self::clientNameOf($event->context->device));
        self::assertSame('password', $event->context->method);
        self::assertEquals(new ClientContext(self::CLIENT_IP, self::CLIENT_AGENT), $event->context->client);
        self::assertSame($pending->expiresAt->getTimestamp(), $event->expiresAt->getTimestamp());
    }

    /**
     * `AuthenticationFailed` for an `attempt()` refused because a further
     * factor is required comes back with the member, membership and tenant
     * reloaded, and its reason and identifier unchanged.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAuthenticationFailedRestoresItsModels(): void
    {
        self::requireAFactor();

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertFalse($this->freshGuard('members')->attempt(self::credentials('member@example.test')));

        $event = self::roundTrip($this->recordedEvent(AuthenticationFailed::class));

        $this->assertRestoredModels($event->context->identity, $event->context->principal, $event->context->tenant);
        self::assertNull($event->context->device);
        self::assertSame(FailureReason::ADDITIONAL_FACTOR_REQUIRED, $event->reason);
        self::assertSame('password', $event->context->method);
        self::assertSame('member@example.test', $event->identifier);
        self::assertSame(self::CLIENT_IP, $event->context->client->ip);
    }

    /**
     * A queued event holds its models as identifiers and never the session's
     * secrets: no token, no refresh digest, no password hash.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAQueuedEventHoldsIdentifiersAndNoSecret(): void
    {
        $this->recordEvents([SignedIn::class]);

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);

        $queued = serialize($this->recordedEvent(SignedIn::class));
        $digest = $session->device->getRefreshKey();
        $hash   = $this->member->getAuthPassword();

        self::assertNotNull($digest);
        self::assertStringContainsString('ModelIdentifier', $queued);
        self::assertStringNotContainsString($session->tokens->accessToken, $queued);
        self::assertStringNotContainsString($session->tokens->refreshToken, $queued);
        self::assertStringNotContainsString($digest, $queued);
        self::assertStringNotContainsString($hash, $queued);
    }

    /**
     * The identifiers an event snapshots when it is built come back unchanged
     * after a queue, beside the models that are loaded again.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheSnapshotsSurviveTheQueue(): void
    {
        $this->recordEvents([SignedIn::class]);

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);

        $context = self::roundTrip($this->recordedEvent(SignedIn::class))->context;

        self::assertSame((string) $this->member->getKey(), $context->identityId); // @phpstan-ignore cast.string
        self::assertSame($this->membership->getMorphClass(), $context->principalType);
        self::assertSame((string) $this->membership->getKey(), $context->principalId); // @phpstan-ignore cast.string
        self::assertSame((string) $this->tenant->getKey(), $context->tenantId); // @phpstan-ignore cast.string
        self::assertSame($session->device->getKey(), $context->deviceId);
    }

    /**
     * A queued listener cannot restore an event whose device was deleted while
     * it waited (a pruned device): Laravel's `ModelNotFoundException` says so,
     * and the snapshots are the record to keep.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEventWhoseDeviceWasDeletedCannotBeRestored(): void
    {
        $this->recordEvents([SignedIn::class]);

        self::assertTrue($this->sessions('members')->signIn('password', self::credentials('member@example.test'))->isSignedIn());

        $queued = serialize($this->recordedEvent(SignedIn::class));

        Device::query()->delete();

        $this->expectException(ModelNotFoundException::class);

        unserialize($queued);
    }

    /**
     * Configure the guards.
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

        self::configureSessionGuards($app->make(ConfigRepository::class));
    }

    /**
     * The event as a queued listener receives it, after the member, the tenant
     * and every device were renamed while it waited.
     *
     * @template TEvent of object
     *
     * @param  TEvent  $event
     * @return TEvent
     */
    private static function roundTrip(object $event): object
    {
        $queued = serialize($event);

        ActivatableTenantMember::query()->update(['email' => 'renamed@example.test']);
        ActivatableTenant::query()->update(['name' => 'Renamed']);
        Device::query()->update(['client_name' => 'Renamed']);

        $copy = unserialize($queued);

        self::assertInstanceOf($event::class, $copy);
        self::assertNotSame($event, $copy);

        return $copy;
    }

    /**
     * The client name stored on a restored device.
     *
     * @param  mixed  $device
     * @return mixed
     */
    private static function clientNameOf(mixed $device): mixed
    {
        self::assertInstanceOf(Device::class, $device);

        return $device->getAttribute('client_name');
    }

    /**
     * Require a further factor of every sign-in.
     *
     * @return void
     */
    private static function requireAFactor(): void
    {
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
    }

    /**
     * Assert the restored identity, principal and tenant are the seeded ones,
     * reloaded as models.
     *
     * @param  mixed  $identity
     * @param  mixed  $principal
     * @param  mixed  $tenant
     * @return void
     */
    private function assertRestoredModels(mixed $identity, mixed $principal, mixed $tenant): void
    {
        self::assertSameModel($this->member, $identity);
        self::assertSameModel($this->membership, $principal);
        self::assertSameModel($this->tenant, $tenant);
        self::assertSame('renamed@example.test', $identity->email); // @phpstan-ignore property.nonObject
        self::assertSame('Renamed', $tenant->name); // @phpstan-ignore property.nonObject
    }

    /**
     * Assert the value is a model reloaded from the database as the expected
     * one, not the instance the event was made with.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $expected
     * @param  mixed  $actual
     * @return void
     */
    private static function assertSameModel(Model $expected, mixed $actual): void
    {
        self::assertInstanceOf($expected::class, $actual);
        self::assertNotSame($expected, $actual);
        self::assertTrue($expected->is($actual));
    }
}
