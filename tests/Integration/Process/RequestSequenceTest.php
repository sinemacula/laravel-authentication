<?php

declare(strict_types = 1);

namespace Tests\Integration\Process;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenantMembership;
use Tests\TestCase;

/**
 * End-to-end tests for one application serving many requests, as Octane and the
 * test kernel do: each request rebinds the request, which resets every package
 * guard already resolved, so nothing one request bound (an identity, a
 * principal, a device, a refusal) is seen by the next, and a dispatcher or a
 * principal resolver swapped in after the guard resolved reaches the guard, its
 * refresh exchange and its session service.
 *
 * The guards are never forgotten between the requests here, unlike the rest of
 * the suite, so a leak would show.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
final class RequestSequenceTest extends TestCase
{
    use InteractsWithSessions;

    /**
     * Freeze the clocks, create the tables, and add the routes: who the `api`
     * guard says is signed in, a sign-in and a logout.
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

        Route::get('/me', function (): array {
            $guard = $this->apiGuard();

            return [
                'identity'  => $guard->id(),
                'principal' => $guard->principal()?->getPrincipalIdentifier(),
                'device'    => $guard->device()?->getDeviceIdentifier(),
            ];
        });

        Route::post('/sign-in', static function (): array {
            $session = Auth::sessions('api')->signIn('password', self::credentials(request()->string('email')->value()))->session;

            return ['signed_in' => $session !== null, 'identity' => Auth::guard('api')->id()];
        });

        Route::post('/logout', static function (): array {
            Auth::guard('api')->id();
            Auth::guard('api')->logout();

            return ['identity' => Auth::guard('api')->id()];
        });

        Route::get('/members/me', static function (): array {
            $guard = Auth::manager()->guard('members');

            assert($guard instanceof JwtGuard);

            return ['principal' => $guard->principal()?->getPrincipalIdentifier()];
        });

        Route::post('/members/switch', static function (): array {
            $target = ActivatableTenantMembership::query()->findOrFail(request()->integer('membership'));
            $result = Auth::sessions('members')->switchPrincipal(request()->string('refresh')->value(), $target);
            $guard  = Auth::manager()->guard('members');

            assert($guard instanceof JwtGuard);

            return ['access' => $result->session?->tokens->accessToken, 'principal' => $guard->principal()?->getPrincipalIdentifier()];
        });
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
     * A request with a token, then one without: the second is a guest.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATokenThenNoToken(): void
    {
        [$ada, $session] = $this->signedIn('ada@example.test');

        $this->me($session)->assertJson(['identity' => $ada->getKey()]);
        $this->me(null)->assertExactJson(['identity' => null, 'principal' => null, 'device' => null]);
    }

    /**
     * A request with one identity's token, then one with another's: the second
     * sees only the second identity, principal and device.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testOneIdentitysTokenThenAnothers(): void
    {
        [, $first]        = $this->signedIn('ada@example.test');
        [$grace, $second] = $this->signedIn('grace@example.test');

        $this->me($first)->assertOk();
        $this->me($second)->assertExactJson([
            'identity'  => $grace->getKey(),
            'principal' => $grace->getKey(),
            'device'    => $second->device->getKey(),
        ]);
    }

    /**
     * A rejected token, then a valid one: the refusal does not stick, and the
     * valid token is reported once, as an authentication.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARejectedTokenThenAValidOne(): void
    {
        [$ada, $session] = $this->signedIn('ada@example.test');

        $this->recordEvents([AuthenticationFailed::class]);

        $this->withToken('not-a-jwt')->getJson('/me')->assertJson(['identity' => null]);
        $this->me($session)->assertJson(['identity' => $ada->getKey()]);

        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());
    }

    /**
     * A sign-in, which binds the guard for the rest of its request, then a
     * request without a token: the second is a guest.
     *
     * @return void
     */
    public function testASignInThenAGuestRequest(): void
    {
        $ada = $this->seedIdentity();

        $this->postJson('/sign-in', ['email' => 'ada@example.test'])->assertJson(['signed_in' => true, 'identity' => $ada->getKey()]);
        $this->me(null)->assertJson(['identity' => null]);
    }

    /**
     * A logout, which keeps the guard signed out for the rest of its request,
     * then a request with a valid token: the second is signed in.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testALogoutThenAValidToken(): void
    {
        [, $first]        = $this->signedIn('ada@example.test');
        [$grace, $second] = $this->signedIn('grace@example.test');

        $this->withToken($first->tokens->accessToken)->postJson('/logout')->assertJson(['identity' => null]);
        $this->me($second)->assertJson(['identity' => $grace->getKey()]);
    }

    /**
     * A switch of the principal a device acts as, between two requests with the
     * same token: the second is refused, though the first was accepted by the
     * same guard.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAPrincipalSwitchThenTheOldPrincipalsToken(): void
    {
        [$ada, $session] = $this->signedIn('ada@example.test');

        $this->me($session)->assertJson(['identity' => $ada->getKey()]);

        Device::query()->whereKey($session->device->getKey())->update(['principal_id' => 'another-principal', 'principal_switched_at' => Carbon::now()]);

        $this->recordEvents([AuthenticationFailed::class]);

        $this->me($session)->assertJson(['identity' => null]);

        self::assertSame(FailureReason::DEVICE_PRINCIPAL_MISMATCH, $this->recordedEvent(AuthenticationFailed::class)->reason);
    }

    /**
     * A real switch of principal in one request, between requests with the old
     * and the new access token: the request that switched is bound to the new
     * principal, the old principal's token is refused on the next request, and
     * the new one acts as the new principal.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testASwitchOfPrincipalThenTheOldAndNewTokens(): void
    {
        [$member, $first, $tenant] = $this->seedMember();

        $second  = ActivatableTenantMembership::query()->create(['identity_id' => $member->getKey(), 'tenant_id' => $tenant->getKey()]);
        $session = Auth::sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);

        $this->flushHeaders();
        $this->withToken($session->tokens->accessToken)->getJson('/members/me')->assertExactJson(['principal' => $first->getKey()]);

        $this->flushHeaders();

        $switched = $this->postJson('/members/switch', ['refresh' => $session->tokens->refreshToken, 'membership' => $second->getKey()]);

        $switched->assertJson(['principal' => $second->getKey()]);

        $access = $switched->json('access');

        self::assertIsString($access);

        $this->flushHeaders();
        $this->withToken($session->tokens->accessToken)->getJson('/members/me')->assertExactJson(['principal' => null]);

        $this->flushHeaders();
        $this->withToken($access)->getJson('/members/me')->assertExactJson(['principal' => $second->getKey()]);
    }

    /**
     * `Event::fake()` after the guard resolved reaches the guard, its refresh
     * exchange and its session service: a replayed refresh token's refusal and
     * revocation, and a sign-in, are all recorded by the fake.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFakeDispatcherAfterResolutionReachesEveryPart(): void
    {
        [, $session] = $this->signedIn('ada@example.test');

        $guard = $this->apiGuard();

        self::assertNotNull($guard->refresh($session->tokens->refreshToken));

        Event::fake([AuthenticationFailed::class, DeviceRevoked::class, SignedIn::class]);

        $later = CarbonImmutable::now()->addMinute();

        Carbon::setTestNow($later);
        CarbonImmutable::setTestNow($later);

        JWT::$timestamp = $later->getTimestamp();

        self::assertNull($guard->refresh($session->tokens->refreshToken));

        $guard->sessions()->signIn('password', self::credentials('ada@example.test'));

        Event::assertDispatched(AuthenticationFailed::class, static fn (AuthenticationFailed $event): bool => $event->reason === FailureReason::ROTATION_REUSE);
        Event::assertDispatched(DeviceRevoked::class);
        Event::assertDispatched(SignedIn::class);
    }

    /**
     * A principal resolver bound after the guard resolved is the one the next
     * request uses.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAResolverBoundAfterResolutionIsTheOneUsed(): void
    {
        [$ada, $session] = $this->signedIn('ada@example.test');

        $this->me($session)->assertJson(['identity' => $ada->getKey()]);

        $resolver = \Mockery::mock(PrincipalResolver::class);
        $resolver->shouldReceive('resolve')->with(\Mockery::type(Identity::class), (string) $ada->getKey())->andReturnNull(); // @phpstan-ignore cast.string

        $this->app?->instance(PrincipalResolver::class, $resolver);

        $this->recordEvents([AuthenticationFailed::class]);

        $this->me($session)->assertJson(['identity' => null]);

        self::assertSame(FailureReason::PRINCIPAL_MISMATCH, $this->recordedEvent(AuthenticationFailed::class)->reason);
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
     * Seed an identity and sign it in on a new device of the `api` guard.
     *
     * @param  string  $email
     * @return array{0: \Tests\Integration\Fixtures\IntegrationIdentity, 1: \SineMacula\Laravel\Authentication\Sessions\SignedInSession}
     *
     * @throws \Throwable
     */
    private function signedIn(string $email): array
    {
        $identity = $this->seedIdentity($email);
        $session  = $this->apiGuard()->sessions()->signIn('password', self::credentials($email))->session;

        self::assertNotNull($session);

        return [$identity, $session];
    }

    /**
     * Ask who is signed in, with the session's access token or none, on the
     * same application and guards as every request before.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function me(?SignedInSession $session): TestResponse
    {
        $this->flushHeaders();

        return $session === null ? $this->getJson('/me') : $this->withToken($session->tokens->accessToken)->getJson('/me');
    }

    /**
     * The `api` guard, as resolved so far.
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function apiGuard(): JwtGuard
    {
        $guard = Auth::manager()->guard('api');

        self::assertInstanceOf(JwtGuard::class, $guard);

        return $guard;
    }
}
