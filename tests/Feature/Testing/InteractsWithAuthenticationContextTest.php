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
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\TenantResolver;
use SineMacula\Laravel\Authentication\Exceptions\TenantUnavailableException;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Testing\Concerns\InteractsWithAuthenticationContext;
use Tests\Concerns\InteractsWithSessions;
use Tests\Fixtures\Tenancy\DescendantTenants;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\ActivatableTenantMember;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * Feature tests for the testing helpers, driven as an application's test suite
 * would: acting as an identity, a principal or a session survives the requests
 * the test sends through `auth:<guard>` routes, ends on a sign-out through a
 * real endpoint and on `stopActing()`, keeps each guard's context apart, and
 * the bound-context assertions pass and fail with what they found.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(InteractsWithAuthenticationContext::class)]
final class InteractsWithAuthenticationContextTest extends TestCase
{
    use InteractsWithAuthenticationContext, InteractsWithSessions;

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

        foreach (['api', 'admin', 'members'] as $guard) {
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
        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * Acting as an identity authenticates every request the test sends through
     * the guard's `auth` middleware, as its default principal and on no
     * session, and makes the guard the default.
     *
     * @return void
     */
    public function testActingAsAnIdentitySurvivesTheRequestsTheTestSends(): void
    {
        $ada = $this->seedIdentity();

        $this->actingAsIdentity($ada, guard: 'api');

        self::assertSame('api', Auth::getDefaultDriver());

        $expected = ['identity' => $ada->getKey(), 'principal' => $ada->getKey(), 'tenant' => null, 'session' => null, 'scopes' => null];

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
     * and session given, on every request, in the tenant the session records
     * (here the tenant of the membership it was signed in as, which the
     * application's resolver finds, not the own tenant of the membership acted
     * as), or, with no session, in the principal's own.
     *
     * @return void
     */
    public function testActingAsAnIdentityWithAPrincipalAndASession(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->signedInSession('members', 'member@example.test');

        [, $other, $otherTenant] = $this->seedMember('other@example.test');

        $other->forceFill(['identity_id' => $member->getKey()])->save();

        app()->instance(TenantResolver::class, new DescendantTenants);

        $this->actingAsIdentity($member, $other, $session, null, 'members');

        $this->getJson('/members/me')->assertOk()->assertExactJson([
            'identity'  => $member->getKey(),
            'principal' => $other->getKey(),
            'tenant'    => $tenant->getKey(),
            'session'   => $session->getKey(),
            'scopes'    => null,
        ]);

        $this->actingAsIdentity($member, $other, guard: 'members');

        $this->getJson('/members/me')->assertOk()->assertExactJson([
            'identity'  => $member->getKey(),
            'principal' => $other->getKey(),
            'tenant'    => $otherTenant->getKey(),
            'session'   => null,
            'scopes'    => null,
        ]);

        $this->actingAsIdentity($member, guard: 'members');

        $this->getJson('/members/me')->assertOk()->assertExactJson([
            'identity'  => $member->getKey(),
            'principal' => $membership->getKey(),
            'tenant'    => $tenant->getKey(),
            'session'   => null,
            'scopes'    => null,
        ]);
    }

    /**
     * Acting on a session whose recorded tenant the application cannot resolve
     * never reads as acting in no tenant: the active tenant throws
     * `TenantUnavailableException` while the context stays bound.
     *
     * @return void
     */
    public function testActingOnASessionWhoseTenantCannotBeResolvedThrowsForTheTenant(): void
    {
        [$member] = $this->seedMember();

        $session = $this->signedInSession('members', 'member@example.test');

        [, $other] = $this->seedMember('other@example.test');

        $other->forceFill(['identity_id' => $member->getKey()])->save();

        $this->actingAsIdentity($member, $other, $session, null, 'members');

        self::assertSame($other, Auth::principal());
        self::assertSame($session, Auth::session());

        $this->expectException(TenantUnavailableException::class);

        Auth::tenant();
    }

    /**
     * Acting in a tenant binds it as the active tenant of the context the test
     * acts as, on every request, until the test acts again; acting in a tenant
     * on a guard the test does not act on is refused.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testActingInATenantBindsItAsTheActiveTenant(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $descendant = ActivatableTenant::query()->create(['name' => 'Descendant', 'is_active' => true]);

        $this->actingAsPrincipal($membership, guard: 'members')->actingInTenant($descendant, 'members');

        $expected = ['identity' => $member->getKey(), 'principal' => $membership->getKey(), 'tenant' => $descendant->getKey(), 'session' => null, 'scopes' => null];

        $this->getJson('/members/me')->assertOk()->assertExactJson($expected);
        $this->getJson('/members/me')->assertOk()->assertExactJson($expected);
        $this->assertBoundTenant($descendant, 'members');

        $this->actingAsPrincipal($membership, guard: 'members');

        $this->getJson('/members/me')->assertOk()->assertJson(['tenant' => $tenant->getKey()]);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The test does not act on guard [admin]');

        $this->actingInTenant($descendant, 'admin');
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
            'session'   => null,
            'scopes'    => null,
        ]);
    }

    /**
     * Acting on a session acts as its owner and the principal it records, on
     * the guard it records, which becomes the default.
     *
     * @return void
     */
    public function testActingOnASessionActsAsItsSession(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->signedInSession('members', 'member@example.test');

        $this->actingOnSession($session);

        self::assertSame('members', Auth::getDefaultDriver());

        $this->getJson('/members/me')->assertOk()->assertExactJson([
            'identity'  => $member->getKey(),
            'principal' => $membership->getKey(),
            'tenant'    => $tenant->getKey(),
            'session'   => $session->getKey(),
            'scopes'    => null,
        ]);

        $this->assertBoundIdentity($member)
            ->assertBoundPrincipal($membership)
            ->assertBoundTenant($tenant)
            ->assertBoundSession($session)
            ->assertBoundScopes(null);
    }

    /**
     * A session of another guard cannot be acted on under a guard it does not
     * record.
     *
     * @return void
     */
    public function testASessionCannotBeActedOnUnderAnotherGuard(): void
    {
        $this->seedMember();

        $session = $this->signedInSession('members', 'member@example.test');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('Session [%s] belongs to guard [members], not [api].', $session->getKey()));

        $this->actingOnSession($session, 'api');
    }

    /**
     * Naming the guard a session records is the same as naming none.
     *
     * @return void
     */
    public function testNamingTheGuardASessionRecords(): void
    {
        $ada     = $this->seedIdentity();
        $session = $this->signedInSession('api', 'ada@example.test');

        $this->actingOnSession($session, 'api')
            ->assertBoundIdentity($ada, 'api')
            ->assertBoundSession($session, 'api');
    }

    /**
     * A session that records no guard is acted on under the guard named, or the
     * default one.
     *
     * @return void
     */
    public function testASessionRecordingNoGuardIsActedOnUnderTheGuardNamed(): void
    {
        $ada     = $this->seedIdentity();
        $session = $this->signedInSession('api', 'ada@example.test');

        $session->forceFill(['guard' => null]);

        Auth::shouldUse('admin');

        $this->actingOnSession($session, 'api')->assertBoundSession($session, 'api');

        self::assertSame('api', Auth::getDefaultDriver());

        Auth::shouldUse('admin');

        $this->actingOnSession($session)->assertBoundIdentity($ada, 'admin')->assertBoundSession($session, 'admin');
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

        $session = $this->signedInSession('members', 'member@example.test');

        $scenario = new class {
            /**
             * Act and assert through the test case as a collaborator would.
             *
             * @param  \Tests\Feature\Testing\InteractsWithAuthenticationContextTest  $test
             * @param  \Tests\Integration\Fixtures\ActivatableTenantMember  $member
             * @param  \Tests\Integration\Fixtures\ActivatableTenantMembership  $membership
             * @param  \Tests\Integration\Fixtures\ActivatableTenant  $tenant
             * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
             * @return void
             */
            public function run(
                InteractsWithAuthenticationContextTest $test,
                ActivatableTenantMember $member,
                ActivatableTenantMembership $membership,
                ActivatableTenant $tenant,
                EloquentSession&Model $session,
            ): void {
                $test->actingAsIdentity($member, guard: 'members')->assertBoundIdentity($member)->assertBoundTenant($tenant);
                $test->actingInTenant($tenant, 'members')->assertBoundTenant($tenant);
                $test->actingAsPrincipal($membership)->assertBoundPrincipal($membership)->assertBoundScopes(null);
                $test->actingOnSession($session)->assertBoundSession($session);
                $test->stopActing()->assertBoundIdentity(null);
            }
        };

        $scenario->run($this, $member, $membership, $tenant, $session);
    }

    /**
     * Signing out through a real endpoint ends acting on the guard: the session
     * acted on is revoked and the next request is unauthenticated.
     *
     * @return void
     */
    public function testSigningOutThroughAnEndpointEndsActing(): void
    {
        $this->seedIdentity();

        $session = $this->signedInSession('api', 'ada@example.test');

        $this->actingOnSession($session);

        $this->postJson('/api/sign-out')->assertNoContent();

        self::assertNotNull($session->refresh()->getRevokedAt());

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
            ->assertBoundSession(null)
            ->assertBoundScopes(null);

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
        $token  = $result->session?->tokens->accessToken->reveal();

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
     * Each assertion fails, naming the guard and what it found, when the bound
     * context is not the one expected.
     *
     * @return void
     */
    public function testEachAssertionFailsWithWhatItFound(): void
    {
        [$member, $membership, $tenant]          = $this->seedMember();
        [$other, $otherMembership, $otherTenant] = $this->seedMember('other@example.test');

        $session = $this->signedInSession('members', 'member@example.test');

        $this->actingOnSession($session);

        $failures = [
            'identity'  => fn () => $this->assertBoundIdentity($other),
            'principal' => fn () => $this->assertBoundPrincipal($otherMembership),
            'tenant'    => fn () => $this->assertBoundTenant($otherTenant),
            'session'   => fn () => $this->assertBoundSession(null),
        ];

        $found = [
            'identity'  => sprintf('%s [%s]', ActivatableTenantMember::class, $member->getKey()),
            'principal' => sprintf('%s [%s]', $membership::class, $membership->getKey()),
            'tenant'    => sprintf('%s [%s]', $tenant::class, $tenant->getKey()),
            'session'   => sprintf('%s [%s]', $session::class, $session->getKey()),
        ];

        foreach ($failures as $kind => $assertion) {
            $message = $this->failureOf($assertion);

            self::assertStringStartsWith(sprintf('Expected the %s bound to guard [members] to be ', $kind), $message);
            self::assertStringContainsString(sprintf(', got %s.', $found[$kind]), $message);
        }

        self::assertStringStartsWith('Unexpected scopes bound to guard [members].', $this->failureOf(fn () => $this->assertBoundScopes([])));
    }

    /**
     * Configure the session guards and a session guard of Laravel's.
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
            'session'   => Auth::session()?->getSessionIdentifier(),
            'scopes'    => Auth::scopes(),
        ];
    }

    /**
     * Sign the identity with the email in on the guard and return its session.
     *
     * @param  string  $guard
     * @param  string  $email
     * @return \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession
     */
    private function signedInSession(string $guard, string $email): EloquentSession&Model
    {
        $session = $this->sessions($guard)->signIn('password', self::credentials($email))->session?->record;

        self::assertNotNull($session);

        Auth::forgetGuards();

        return $session;
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
