<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Authenticated;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Login;
use Illuminate\Auth\Events\Validated;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceAuthenticated;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;
use SineMacula\Laravel\Authentication\Events\SignedIn;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\BearerAuthentication;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Guards\OwnedDevice;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\ActivatableTenant;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * End-to-end tests for the events of a request's access token, against a real
 * database on whichever engine the suite runs on. A request's token is an
 * authentication, not a sign-in: it reports only `Authenticated` and the
 * package's contextual events, and a rejected one only `AuthenticationFailed`
 * with the reason the real rows give, never Laravel's `Attempting`,
 * `Validated`, `Login` or `Failed`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BearerAuthentication::class)]
#[CoversClass(OwnedDevice::class)]
#[CoversClass(JwtGuard::class)]
final class BearerAuthenticationTest extends TestCase
{
    use InteractsWithSessions;

    /** @var list<class-string> Every event a bearer request could dispatch. */
    private const array OBSERVED = [
        Attempting::class,
        Validated::class,
        Login::class,
        Failed::class,
        Authenticated::class,
        PrincipalAssigned::class,
        DeviceAuthenticated::class,
        SignedIn::class,
        AuthenticationFailed::class,
    ];

    /**
     * Freeze the clocks, create the tables, and add a route behind the `auth`
     * middleware of each guard.
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

        Route::middleware('auth:api')->get('/me', static fn (): array => ['identity' => Auth::id()]);
        Route::middleware('auth:members')->get('/members/me', static fn (): array => ['identity' => Auth::guard('members')->id()]);
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
     * A valid access token authenticates the request with exactly
     * `Authenticated`, `PrincipalAssigned` and `DeviceAuthenticated`, which
     * carry the guard, the request's client, the identity, the device and the
     * method its session records.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABearerRequestReportsOnlyTheAuthentication(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn();

        $this->recordEvents(self::OBSERVED);

        $this->bearer($session->tokens->accessToken)->assertOk()->assertJson(['identity' => $identity->getKey()]);

        self::assertSame([Authenticated::class, PrincipalAssigned::class, DeviceAuthenticated::class], $this->recordedClasses());

        $context = $this->recordedEvent(DeviceAuthenticated::class)->context;

        self::assertSame('api', $context->guard);
        self::assertSame('198.51.100.20', $context->client->ip);
        self::assertSame('Bearer/1.0', $context->client->userAgent);
        self::assertSame((string) $identity->getKey(), $context->identityId); // @phpstan-ignore cast.string
        self::assertSame($session->device->getKey(), $context->deviceId);
        self::assertSame('password', $context->method);
        self::assertSame($context, $this->recordedEvent(PrincipalAssigned::class)->context);
    }

    /**
     * A member's token reports the tenant its membership's activity check
     * loaded.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testABearerRequestReportsTheTenant(): void
    {
        [$member, $membership, $tenant] = $this->seedMember();

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);

        $this->recordEvents([PrincipalAssigned::class]);

        $this->bearer($session->tokens->accessToken, '/members/me')->assertOk()->assertJson(['identity' => $member->getKey()]);

        $context = $this->recordedEvent(PrincipalAssigned::class)->context;

        self::assertSame((string) $membership->getKey(), $context->principalId); // @phpstan-ignore cast.string
        self::assertSame((string) $tenant->getKey(), $context->tenantId); // @phpstan-ignore cast.string
    }

    /**
     * A request without a token attempts nothing and dispatches nothing.
     *
     * @return void
     */
    public function testARequestWithoutATokenDispatchesNothing(): void
    {
        $this->recordEvents(self::OBSERVED);

        $this->getJson('/me')->assertUnauthorized();

        self::assertSame([], $this->recorded);
    }

    /**
     * Rows of `[what the rows say, the reason]`: each way the real rows make a
     * token fail, after it was issued.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \Closure(\Tests\Integration\Fixtures\IntegrationIdentity, \SineMacula\Laravel\Authentication\Sessions\SignedInSession): ?string, 1: \SineMacula\Laravel\Authentication\Events\Enums\FailureReason}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideRejections(): iterable
    {
        yield 'a token that is not one' => [static fn (): string => 'not-a-jwt', FailureReason::TOKEN_INVALID];
        yield 'a deleted identity' => [static function (IntegrationIdentity $identity): ?string {
            $identity->delete();

            return null;
        }, FailureReason::IDENTITY_UNKNOWN];
        yield 'a deactivated identity' => [static function (IntegrationIdentity $identity): ?string {
            $identity->forceFill(['is_active' => false])->save();

            return null;
        }, FailureReason::IDENTITY_INACTIVE];
        yield 'another identity named as the principal' => [static function (IntegrationIdentity $identity, SignedInSession $session): string {
            $other = new IntegrationIdentity;
            $other->forceFill(['email' => 'grace@example.test', 'password' => 'x', 'is_active' => true])->save();

            $tokens = Auth::jwt('api');

            self::assertNotNull($tokens);

            return $tokens->issueAccessToken($identity, $other, $session->device);
        }, FailureReason::PRINCIPAL_MISMATCH];
        yield 'a deleted device' => [static function (IntegrationIdentity $identity, SignedInSession $session): ?string {
            Device::query()->whereKey($session->device->getKey())->delete();

            return null;
        }, FailureReason::DEVICE_UNKNOWN];
        yield 'a device of another guard' => [static function (IntegrationIdentity $identity, SignedInSession $session): ?string {
            Device::query()->whereKey($session->device->getKey())->update(['guard' => 'admin']);

            return null;
        }, FailureReason::DEVICE_GUARD_MISMATCH];
        yield 'a revoked device' => [static function (IntegrationIdentity $identity, SignedInSession $session): ?string {
            Device::query()->whereKey($session->device->getKey())->update(['revoked_at' => Carbon::now(), 'revoked_reason' => 'revoked']);

            return null;
        }, FailureReason::DEVICE_REVOKED];
        yield 'an ended session' => [static function (IntegrationIdentity $identity, SignedInSession $session): ?string {
            Device::query()->whereKey($session->device->getKey())->update(['idle_expires_at' => Carbon::now()]);

            return null;
        }, FailureReason::SESSION_EXPIRED];
    }

    /**
     * A token the rows reject is answered `401` and reported once, as
     * `AuthenticationFailed` for the bearer flow with the reason, attributed to
     * the guard and the client, and nothing else is dispatched.
     *
     * @param  \Closure(\Tests\Integration\Fixtures\IntegrationIdentity, \SineMacula\Laravel\Authentication\Sessions\SignedInSession): ?string  $change
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideRejections')]
    public function testATokenTheRowsRejectIsReportedOnceWithItsReason(\Closure $change, FailureReason $reason): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn();
        $token    = $change($identity, $session) ?? $session->tokens->accessToken;

        $this->recordEvents(self::OBSERVED);

        $this->bearer($token)->assertUnauthorized();

        self::assertSame([AuthenticationFailed::class], $this->recordedClasses());

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(AuthenticationFlow::BEARER, $failure->flow);
        self::assertSame($reason, $failure->reason);
        self::assertSame('api', $failure->context->guard);
        self::assertSame('198.51.100.20', $failure->context->client->ip);
        self::assertNull($failure->identifier);
        self::assertNull($failure->retryAfter);
    }

    /**
     * A device failure is attributed to the identity, the principal and the
     * device the rows hold, with the method the device's session records; a
     * missing device keeps the id the token named.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeviceFailureCarriesTheContextItEstablished(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signedIn();
        $deviceId = $session->device->getKey();

        Device::query()->whereKey($deviceId)->update(['revoked_at' => Carbon::now(), 'revoked_reason' => 'revoked']);

        $this->recordEvents([AuthenticationFailed::class]);

        $this->bearer($session->tokens->accessToken)->assertUnauthorized();

        $revoked = $this->recordedEvent(AuthenticationFailed::class)->context;

        Device::query()->whereKey($deviceId)->delete();

        $this->recordEvents([AuthenticationFailed::class]);

        $this->bearer($session->tokens->accessToken)->assertUnauthorized();

        $missing = $this->recordedEvent(AuthenticationFailed::class)->context;

        self::assertSame((string) $identity->getKey(), $revoked->identityId); // @phpstan-ignore cast.string
        self::assertSame((string) $identity->getKey(), $revoked->principalId); // @phpstan-ignore cast.string
        self::assertSame($deviceId, $revoked->device?->getDeviceIdentifier());
        self::assertSame('password', $revoked->method);
        self::assertNull($missing->device);
        self::assertSame($deviceId, $missing->deviceId);
        self::assertNull($missing->method);
    }

    /**
     * A member whose tenant is deactivated after the token was issued is
     * rejected as `tenant_inactive`, attributed to the member and membership.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADeactivatedTenantRejectsItsMembersTokens(): void
    {
        [$member, $membership] = $this->seedMember();

        $session = $this->sessions('members')->signIn('password', self::credentials('member@example.test'))->session;

        self::assertNotNull($session);

        ActivatableTenant::query()->update(['is_active' => false]);

        $this->recordEvents([AuthenticationFailed::class]);

        $this->bearer($session->tokens->accessToken, '/members/me')->assertUnauthorized();

        $failure = $this->recordedEvent(AuthenticationFailed::class);

        self::assertSame(FailureReason::TENANT_INACTIVE, $failure->reason);
        self::assertSame('members', $failure->context->guard);
        self::assertSame((string) $member->getKey(), $failure->context->identityId); // @phpstan-ignore cast.string
        self::assertSame((string) $membership->getKey(), $failure->context->principalId); // @phpstan-ignore cast.string
        self::assertNull($failure->context->tenant);
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
     * Sign the seeded identity in on a new device of the `api` guard.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signedIn(): SignedInSession
    {
        $session = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);
        self::assertSame(1, DB::table('devices')->count());

        return $session;
    }

    /**
     * Send a request with the bearer token from a known client.
     *
     * @param  string  $token
     * @param  string  $uri
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(string $token, string $uri = '/me'): TestResponse
    {
        Auth::forgetGuards();

        return $this->withServerVariables(['REMOTE_ADDR' => '198.51.100.20'])
            ->withHeaders(['Authorization' => 'Bearer ' . $token, 'User-Agent' => 'Bearer/1.0'])
            ->getJson($uri);
    }
}
