<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing;

use Illuminate\Auth\Events\Logout;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Foundation\Application;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\EloquentDevice;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Testing\Concerns\InteractsWithAuthenticationContext;
use Tests\Concerns\InteractsWithSessions;
use Tests\Concerns\InteractsWithTypedPrincipals;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\Integration\Fixtures\TypedIdentity;
use Tests\Integration\Fixtures\TypedMembership;
use Tests\Integration\Fixtures\TypedTenant;
use Tests\TestCase;

/**
 * Feature tests for the testing helpers, driven as an application's test suite
 * would: acting as an identity, a principal or a device's session survives the
 * requests the test sends through `auth:<guard>` routes, ends on a sign-out
 * through a real endpoint and on `stopActing()`, keeps each guard's context
 * apart, and the bound-context assertions pass and fail with what they found.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(InteractsWithAuthenticationContext::class)]
final class InteractsWithAuthenticationContextTest extends TestCase
{
    use InteractsWithAuthenticationContext, InteractsWithSessions, InteractsWithTypedPrincipals;

    /**
     * Create the tables and register routes behind each guard's `auth`
     * middleware that answer with what the request is authenticated as, and a
     * sign-out endpoint.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();
        self::createTypedPrincipalTables();

        foreach (['api', 'admin', 'members', 'typed'] as $guard) {
            Route::middleware('auth:' . $guard)->get('/' . $guard . '/me', self::context(...));
        }

        Route::middleware('auth:api')->post('/api/sign-out', static function (): Response {

            Auth::guard('api')->logout();

            return response()->noContent();
        });

        Route::middleware('auth:api')->get('/api/me/model', static fn (): ?Model => Auth::identity() instanceof Model ? Auth::identity() : null);
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropTypedPrincipalTables();
        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * Acting as an identity authenticates every request the test sends through
     * the guard's `auth` middleware, as its default principal and on no device,
     * and makes the guard the default.
     *
     * @return void
     */
    public function testActingAsAnIdentitySurvivesTheRequestsTheTestSends(): void
    {
        $ada = $this->seedIdentity();

        $this->actingAsIdentity($ada, guard: 'api');

        self::assertSame('api', Auth::getDefaultDriver());

        $expected = ['identity' => $ada->getKey(), 'principal' => $ada->getKey(), 'tenant' => null, 'device' => null, 'scopes' => null];

        $this->getJson('/api/me')->assertOk()->assertExactJson($expected);
        $this->getJson('/api/me')->assertOk()->assertExactJson($expected);
    }

    /**
     * Laravel's own `actingAs()` is left as it is: it binds the guard for code
     * that runs in the test, and a request through the kernel starts over.
     *
     * @return void
     */
    public function testLaravelsActingAsKeepsItsLimit(): void
    {
        $ada = $this->seedIdentity();

        $this->actingAs($ada, 'api');

        self::assertSame($ada, Auth::identity());

        $this->getJson('/api/me')->assertUnauthorized();
    }

    /**
     * Acting as an identity of a three-dimensional guard binds the principal
     * and device given, and the tenant the principal acts within, on every
     * request.
     *
     * @return void
     */
    public function testActingAsAnIdentityWithAPrincipalAndADevice(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $device = $this->signedInDevice('members', 'member@example.test');

        [, $other] = $this->seedMember('other@example.test');

        $other->forceFill(['identity_id' => $member->getKey()])->save();

        $this->actingAsIdentity($member, $other, $device, 'members');

        $this->getJson('/members/me')->assertOk()->assertExactJson([
            'identity'  => $member->getKey(),
            'principal' => $other->getKey(),
            'tenant'    => $other->tenant_id,
            'device'    => $device->getKey(),
            'scopes'    => null,
        ]);

        $this->actingAsIdentity($member, guard: 'members');

        $this->getJson('/members/me')->assertOk()->assertExactJson([
            'identity'  => $member->getKey(),
            'principal' => $membership->getKey(),
            'tenant'    => $tenant->getKey(),
            'device'    => null,
            'scopes'    => null,
        ]);
    }

    /**
     * An identity with no default principal cannot be acted as without naming
     * one, as `setUser()` refuses it.
     *
     * @return void
     */
    public function testAnIdentityWithoutADefaultPrincipalNeedsOneNamed(): void
    {
        $member = ActivatableTenantMember::query()->create(['email' => 'alone@example.test', 'password' => 'irrelevant']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('Guard members could not resolve a default principal for identity %s;', ActivatableTenantMember::class));

        $this->actingAsIdentity($member, guard: 'members');
    }

    /**
     * Scopes limit a machine identity's credential, so acting as a human with
     * scopes is refused, and nothing is acted as: the next request is
     * unauthenticated.
     *
     * @return void
     */
    public function testAHumanCannotBeActedAsWithScopes(): void
    {
        $ada = $this->seedIdentity();

        try {
            $this->actingAsIdentity($ada, guard: 'api', scopes: ['reports:read']);
            self::fail('A human was acted as with scopes.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame(sprintf('Scopes limit the credential of a machine identity; %s is not one, so no credential limits it.', $ada::class), $exception->getMessage());
        }

        $this->getJson('/api/me')->assertUnauthorized();
    }

    /**
     * Acting as a principal acts for the identity that owns it.
     *
     * @return void
     */
    public function testActingAsAPrincipalActsForItsIdentity(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $this->actingAsPrincipal($membership, guard: 'members');

        $this->getJson('/members/me')->assertOk()->assertExactJson([
            'identity'  => $member->getKey(),
            'principal' => $membership->getKey(),
            'tenant'    => $tenant->getKey(),
            'device'    => null,
            'scopes'    => null,
        ]);
    }

    /**
     * Acting on a device's session acts as its owner and the principal it
     * records, on the guard it records, which becomes the default.
     *
     * @return void
     */
    public function testActingOnADeviceActsAsItsSession(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $device = $this->signedInDevice('members', 'member@example.test');

        $this->actingOnDevice($device);

        self::assertSame('members', Auth::getDefaultDriver());

        $this->getJson('/members/me')->assertOk()->assertExactJson([
            'identity'  => $member->getKey(),
            'principal' => $membership->getKey(),
            'tenant'    => $tenant->getKey(),
            'device'    => $device->getKey(),
            'scopes'    => null,
        ]);

        $this->assertBoundIdentity($member)
            ->assertBoundPrincipal($membership)
            ->assertBoundTenant($tenant)
            ->assertBoundDevice($device)
            ->assertBoundScopes(null)
            ->assertBoundType(null);
    }

    /**
     * A device of another guard cannot be acted on under a guard it does not
     * record.
     *
     * @return void
     */
    public function testADeviceCannotBeActedOnUnderAnotherGuard(): void
    {
        $this->seedMember();

        $device = $this->signedInDevice('members', 'member@example.test');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('Device [%s] belongs to guard [members], not [api].', $device->getKey()));

        $this->actingOnDevice($device, 'api');
    }

    /**
     * Naming the guard a device records is the same as naming none.
     *
     * @return void
     */
    public function testNamingTheGuardADeviceRecords(): void
    {
        $ada    = $this->seedIdentity();
        $device = $this->signedInDevice('api', 'ada@example.test');

        $this->actingOnDevice($device, 'api')
            ->assertBoundIdentity($ada, 'api')
            ->assertBoundDevice($device, 'api');
    }

    /**
     * A device that records no guard is acted on under the guard named, or the
     * default one.
     *
     * @return void
     */
    public function testADeviceRecordingNoGuardIsActedOnUnderTheGuardNamed(): void
    {
        $ada    = $this->seedIdentity();
        $device = $this->signedInDevice('api', 'ada@example.test');

        $device->forceFill(['guard' => null]);

        Auth::shouldUse('admin');

        $this->actingOnDevice($device, 'api')->assertBoundDevice($device, 'api');

        self::assertSame('api', Auth::getDefaultDriver());

        Auth::shouldUse('admin');

        $this->actingOnDevice($device)->assertBoundIdentity($ada, 'admin')->assertBoundDevice($device, 'admin');
    }

    /**
     * The helpers are public, so code outside the test case, a scenario object
     * shared between tests say, can act and assert through it.
     *
     * @return void
     */
    public function testTheHelpersCanBeCalledFromOutsideTheTestCase(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $device = $this->signedInDevice('members', 'member@example.test');

        $scenario = new class {
            /**
             * Act and assert through the test case as a collaborator would.
             *
             * @param  \Tests\Feature\Testing\InteractsWithAuthenticationContextTest  $test
             * @param  \Tests\Integration\Fixtures\ActivatableTenantMember  $member
             * @param  \Tests\Integration\Fixtures\ActivatableTenantMembership  $membership
             * @param  \Tests\Integration\Fixtures\ActivatableTenant  $tenant
             * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice  $device
             * @return void
             */
            public function run(
                InteractsWithAuthenticationContextTest $test,
                ActivatableTenantMember $member,
                ActivatableTenantMembership $membership,
                ActivatableTenant $tenant,
                EloquentDevice&Model $device,
            ): void {
                $test->actingAsIdentity($member, guard: 'members')->assertBoundIdentity($member)->assertBoundTenant($tenant);
                $test->actingAsPrincipal($membership)->assertBoundPrincipal($membership)->assertBoundScopes(null)->assertBoundType(null);
                $test->actingOnDevice($device)->assertBoundDevice($device);
                $test->stopActing()->assertBoundIdentity(null);
            }
        };

        $scenario->run($this, $member, $membership, $tenant, $device);
    }

    /**
     * Signing out through a real endpoint ends acting on the guard: the device
     * acted on is revoked and the next request is unauthenticated.
     *
     * @return void
     */
    public function testSigningOutThroughAnEndpointEndsActing(): void
    {
        $this->seedIdentity();

        $device = $this->signedInDevice('api', 'ada@example.test');

        $this->actingOnDevice($device);

        $this->postJson('/api/sign-out')->assertNoContent();

        self::assertNotNull($device->refresh()->getRevokedAt());

        $this->getJson('/api/me')->assertUnauthorized();
    }

    /**
     * With `Logout` faked the helpers cannot see a sign-out, so acting goes on
     * until the test stops it.
     *
     * @return void
     */
    public function testAFakedLogoutLeavesActingToStopActing(): void
    {
        $ada = $this->seedIdentity();

        Event::fake([Logout::class]);

        $this->actingAsIdentity($ada, guard: 'api');

        $this->postJson('/api/sign-out')->assertNoContent();

        Event::assertDispatched(Logout::class);

        $this->getJson('/api/me')->assertOk();

        $this->stopActing();

        $this->getJson('/api/me')->assertUnauthorized();
    }

    /**
     * `stopActing()` signs the guard out for the rest of the request, and the
     * next request is unauthenticated.
     *
     * @return void
     */
    public function testStopActingEndsIt(): void
    {
        $ada = $this->seedIdentity();

        $this->actingAsIdentity($ada, guard: 'api')
            ->assertBoundIdentity($ada)
            ->stopActing('api')
            ->assertBoundIdentity(null)
            ->assertBoundPrincipal(null)
            ->assertBoundTenant(null)
            ->assertBoundDevice(null)
            ->assertBoundScopes(null)
            ->assertBoundType(null);

        $this->getJson('/api/me')->assertUnauthorized();
    }

    /**
     * Each guard keeps its own context: acting on a second guard leaves the
     * first acting, and stopping one leaves the other.
     *
     * @return void
     */
    public function testEachGuardKeepsItsOwnContext(): void
    {
        $ada   = $this->seedIdentity();
        $grace = $this->seedIdentity('grace@example.test');

        $this->actingAsIdentity($ada, guard: 'api');
        $this->actingAsIdentity($grace, guard: 'admin');

        self::assertSame('admin', Auth::getDefaultDriver());

        $this->getJson('/api/me')->assertOk()->assertJsonPath('identity', $ada->getKey());
        $this->getJson('/admin/me')->assertOk()->assertJsonPath('identity', $grace->getKey());

        $this->assertBoundIdentity($grace)->assertBoundIdentity($ada, 'api');

        $this->stopActing('admin');

        $this->getJson('/admin/me')->assertUnauthorized();
        $this->getJson('/api/me')->assertOk()->assertJsonPath('identity', $ada->getKey());
    }

    /**
     * Acting again on a guard replaces its context.
     *
     * @return void
     */
    public function testActingAgainReplacesTheContext(): void
    {
        $ada   = $this->seedIdentity();
        $grace = $this->seedIdentity('grace@example.test');

        $this->actingAsIdentity($ada, guard: 'api')->actingAsIdentity($grace, guard: 'api');

        $this->getJson('/api/me')->assertOk()->assertJsonPath('identity', $grace->getKey());
    }

    /**
     * A context acted as wins over the credential the request carries.
     *
     * @return void
     */
    public function testTheContextActedAsWinsOverTheRequestsCredential(): void
    {
        $ada   = $this->seedIdentity();
        $grace = $this->seedIdentity('grace@example.test');

        $result = $this->sessions('api')->signIn('password', self::credentials('grace@example.test'));
        $token  = $result->session?->tokens->accessToken;

        self::assertIsString($token);

        $this->withToken($token)->getJson('/api/me')->assertOk()->assertJsonPath('identity', $grace->getKey());

        $this->actingAsIdentity($ada, guard: 'api');

        $this->withToken($token)->getJson('/api/me')->assertOk()->assertJsonPath('identity', $ada->getKey());
    }

    /**
     * A model created for the test answers as an existing one, as with
     * Laravel's `actingAs()`, so a route that returns it is not a `201`.
     *
     * @return void
     */
    public function testAJustCreatedIdentityIsNotAnsweredAsCreated(): void
    {
        $ada = $this->seedIdentity();

        self::assertTrue($ada->wasRecentlyCreated);

        $this->actingAsIdentity($ada, guard: 'api');

        self::assertFalse($ada->wasRecentlyCreated);

        $this->getJson('/api/me/model')->assertOk()->assertJsonPath('email', 'ada@example.test');
    }

    /**
     * The principal's type is asserted from the principal, else its tenant.
     *
     * @return void
     */
    public function testTheBoundTypeIsThePrincipalsOrItsTenants(): void
    {
        $identity = TypedIdentity::query()->create(['email' => 'typed@example.test', 'password' => 'irrelevant']);
        $tenant   = TypedTenant::query()->create(['category' => 'agency']);
        $typed    = TypedMembership::query()->create(['identity_id' => $identity->getKey(), 'tenant_id' => $tenant->getKey(), 'type' => 'staff']);
        $untyped  = TypedMembership::query()->create(['identity_id' => $identity->getKey(), 'tenant_id' => $tenant->getKey(), 'type' => null]);

        $this->actingAsPrincipal($typed, guard: 'typed')->assertBoundType('staff')->assertBoundTenant($tenant);

        $this->getJson('/typed/me')->assertOk()->assertJsonPath('type', 'staff');

        $this->actingAsPrincipal($untyped, guard: 'typed')->assertBoundType('agency');
    }

    /**
     * Each assertion fails, naming the guard and what it found, when the bound
     * context is not the one expected.
     *
     * @return void
     */
    public function testEachAssertionFailsWithWhatItFound(): void
    {
        [$member, $membership, $tenant]          = $this->seedMember();
        [$other, $otherMembership, $otherTenant] = $this->seedMember('other@example.test');

        $device = $this->signedInDevice('members', 'member@example.test');

        $this->actingOnDevice($device);

        $failures = [
            'identity'  => fn () => $this->assertBoundIdentity($other),
            'principal' => fn () => $this->assertBoundPrincipal($otherMembership),
            'tenant'    => fn () => $this->assertBoundTenant($otherTenant),
            'device'    => fn () => $this->assertBoundDevice(null),
        ];

        $found = [
            'identity'  => sprintf('%s [%s]', ActivatableTenantMember::class, $member->getKey()),
            'principal' => sprintf('%s [%s]', $membership::class, $membership->getKey()),
            'tenant'    => sprintf('%s [%s]', $tenant::class, $tenant->getKey()),
            'device'    => sprintf('%s [%s]', $device::class, $device->getKey()),
        ];

        foreach ($failures as $kind => $assertion) {
            $message = $this->failureOf($assertion);

            self::assertStringStartsWith(sprintf('Expected the %s bound to guard [members] to be ', $kind), $message);
            self::assertStringContainsString(sprintf(', got %s.', $found[$kind]), $message);
        }

        self::assertStringStartsWith('Unexpected scopes bound to guard [members].', $this->failureOf(fn () => $this->assertBoundScopes([])));
        self::assertStringStartsWith('Unexpected principal type bound to guard [members].', $this->failureOf(fn () => $this->assertBoundType('staff')));
    }

    /**
     * Configure the session guards, a guard over the typed principals, and a
     * session guard of Laravel's.
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

        $config->set('auth.providers.typed', ['driver' => 'model', 'model' => TypedIdentity::class]);
        $config->set('auth.guards.typed', ['driver' => 'jwt', 'provider' => 'typed']);
    }

    /**
     * What the request is authenticated as on the route's guard.
     *
     * @return array<string, mixed>
     */
    private static function context(): array
    {
        return [
            'identity'  => Auth::identity()?->getAuthIdentifier(),
            'principal' => Auth::principal()?->getPrincipalIdentifier(),
            'tenant'    => Auth::tenant()?->getTenantIdentifier(),
            'device'    => Auth::device()?->getDeviceIdentifier(),
            'scopes'    => Auth::scopes(),
            ...(Auth::type() === null ? [] : ['type' => Auth::type()]),
        ];
    }

    /**
     * Sign the identity with the email in on the guard and return the device
     * its session lives on.
     *
     * @param  string  $guard
     * @param  string  $email
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentDevice
     */
    private function signedInDevice(string $guard, string $email): EloquentDevice&Model
    {
        $device = $this->sessions($guard)->signIn('password', self::credentials($email))->session?->device;

        self::assertNotNull($device);

        Auth::forgetGuards();

        return $device;
    }

    /**
     * The message of the assertion failure the callback raises.
     *
     * @param  \Closure(): mixed  $assertion
     * @return string
     */
    private function failureOf(\Closure $assertion): string
    {
        try {
            $assertion();
        } catch (AssertionFailedError $failure) {
            return $failure->getMessage();
        }

        self::fail('The assertion passed.');
    }
}
