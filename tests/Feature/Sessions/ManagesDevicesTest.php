<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Illuminate\Auth\Events\Logout;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\DeviceRevoked;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\SignedOutEverywhere;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Sessions\Concerns\ManagesDevices;
use SineMacula\Laravel\Authentication\Sessions\DeviceRevocations;
use SineMacula\Laravel\Authentication\Sessions\IdentityDevices;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Feature tests of sign-out and revocation routes an application registers
 * behind `auth:api`, driven over HTTP: `Auth::logout()` revokes the request's
 * device, so its access and refresh tokens stop at once; signing out everywhere
 * ends every other session, optionally keeping the current one; and a device
 * list revokes only the signed-in identity's own devices.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionService::class)]
#[CoversClass(DeviceRevocations::class)]
#[CoversClass(JwtGuard::class)]
#[CoversClass(IdentityDevices::class)]
#[CoversTrait(ManagesDevices::class)]
final class ManagesDevicesTest extends TestCase
{
    use InteractsWithSessions;

    /**
     * Create the tables and register the routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        Route::middleware('auth:api')->group(static function (): void {

            Route::get('/me', static fn (): array => ['id' => Auth::identity()?->getAuthIdentifier()]);

            Route::post('/logout', static function (): array {
                Auth::logout();

                return ['guest' => Auth::guard('api')->guest()];
            });

            Route::post('/logout-everywhere', static fn (Request $request): array => [
                'revoked' => Auth::sessions('api')->signOutEverywhere($request->boolean('keep')),
            ]);

            Route::delete('/devices/{device}', static function (string $device): array {

                $identity = Auth::identity();

                assert($identity instanceof Identity);

                return ['revoked' => Auth::sessions('api')->revokeDevice($identity, $device, RevocationReason::REVOKED)];
            });
        });
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
     * Logging out revokes the request's device as `signed_out` and leaves the
     * guard signed out; the same access token is refused on the next request
     * and the session's refresh token fails as `device_revoked`.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testLogoutRevokesTheDeviceSoItsTokensStopAtOnce(): void
    {
        $this->seedIdentity();

        $session = $this->signIn('Phone');

        $this->recordEvents([DeviceRevoked::class, Logout::class]);

        $this->send('post', '/logout', $session)->assertOk()->assertExactJson(['guest' => true]);

        self::assertSame([DeviceRevoked::class, Logout::class], $this->recordedClasses());

        $revoked = $this->recordedEvent(DeviceRevoked::class);

        self::assertSame(RevocationReason::SIGNED_OUT, $revoked->reason);
        self::assertSame('api', $revoked->context->guard);
        self::assertSame(self::idOf($session), $revoked->context->deviceId);
        self::assertSame('password', $revoked->context->method);
        self::assertSame('127.0.0.1', $revoked->context->client->ip);
        self::assertSame('signed_out', DB::table('devices')->value('revoked_reason'));

        $this->send('get', '/me', $session)->assertUnauthorized();

        $this->recordEvents([AuthenticationFailed::class]);

        self::assertNull($this->freshGuard()->refresh($session->tokens->refreshToken));
        self::assertSame(FailureReason::DEVICE_REVOKED, $this->recordedEvent(AuthenticationFailed::class)->reason);
    }

    /**
     * Signing out everywhere while keeping the current device ends every other
     * session of the identity, of every guard, and keeps the request's own
     * session working; without keeping it, every session ends.
     *
     * @return void
     */
    public function testSigningOutEverywhereEndsTheOtherSessions(): void
    {
        $this->seedIdentity();

        $current = $this->signIn('Phone');
        $other   = $this->signIn('Laptop');
        $admin   = $this->signIn('Console', 'admin');

        $this->recordEvents([DeviceRevoked::class, SignedOutEverywhere::class]);

        $this->send('post', '/logout-everywhere', $current, ['keep' => true])->assertOk()->assertExactJson(['revoked' => 2]);

        self::assertSame([DeviceRevoked::class, DeviceRevoked::class, SignedOutEverywhere::class], $this->recordedClasses());

        $everywhere = $this->recordedEvent(SignedOutEverywhere::class);

        self::assertSame(2, $everywhere->revoked);
        self::assertSame(RevocationReason::SIGNED_OUT_EVERYWHERE, $everywhere->reason);
        self::assertSame(self::idOf($current), $everywhere->context->deviceId);
        self::assertNull($everywhere->tokensValidAfter);
        self::assertEqualsCanonicalizing(['api', 'admin'], array_map(static fn (DeviceRevoked $event): ?string => $event->context->guard, array_slice($this->recorded, 0, 2)));

        $this->send('get', '/me', $current)->assertOk();
        $this->send('get', '/me', $other)->assertUnauthorized();
        self::assertNull(DB::table('devices')->where('id', self::idOf($current))->value('revoked_at'));
        self::assertNotNull(DB::table('devices')->where('id', self::idOf($admin))->value('revoked_at'));

        $this->send('post', '/logout-everywhere', $current)->assertOk()->assertExactJson(['revoked' => 1]);
        $this->send('get', '/me', $current)->assertUnauthorized();
    }

    /**
     * A device list revokes only the signed-in identity's own devices: another
     * identity's device, an unknown one and a malformed id are all simply not
     * found, and revoking a device twice reports it once.
     *
     * @return void
     */
    public function testADeviceListRevokesOnlyItsOwnDevices(): void
    {
        $this->seedIdentity();
        $this->seedIdentity('grace@example.test');

        $current = $this->signIn('Phone');
        $laptop  = $this->signIn('Laptop');
        $theirs  = $this->signIn('Theirs', 'api', 'grace@example.test');

        $this->recordEvents([DeviceRevoked::class]);

        $this->send('delete', '/devices/' . self::idOf($theirs), $current)->assertOk()->assertExactJson(['revoked' => false]);
        $this->send('delete', '/devices/0190e1a4-0000-7000-8000-000000000000', $current)->assertOk()->assertExactJson(['revoked' => false]);
        $this->send('delete', '/devices/not-a-key', $current)->assertOk()->assertExactJson(['revoked' => false]);

        self::assertSame([], $this->recorded);
        self::assertSame(0, DB::table('devices')->whereNotNull('revoked_at')->count());

        $this->send('delete', '/devices/' . self::idOf($laptop), $current)->assertOk()->assertExactJson(['revoked' => true]);
        $this->send('delete', '/devices/' . self::idOf($laptop), $current)->assertOk()->assertExactJson(['revoked' => false]);

        $revoked = $this->recordedEvent(DeviceRevoked::class);

        self::assertSame(RevocationReason::REVOKED, $revoked->reason);
        self::assertSame(self::idOf($laptop), $revoked->context->deviceId);
        self::assertSame('revoked', DB::table('devices')->where('id', self::idOf($laptop))->value('revoked_reason'));

        $this->send('get', '/me', $laptop)->assertUnauthorized();
        $this->send('get', '/me', $theirs)->assertOk();
    }

    /**
     * The device list holds fifteen devices to a page unless asked otherwise,
     * the request's own device marked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheDeviceListHoldsFifteenToAPageByDefault(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->signIn('Phone');

        $guard = $this->freshGuard();
        $guard->login($identity, $identity, $session->device);

        $page = $guard->sessions()->devices($identity);

        self::assertSame(15, $page->perPage());
        self::assertTrue($page->items()[0]->current);
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
     * Sign the identity in on the guard, from a client of the given name.
     *
     * @param  string  $client
     * @param  string  $guard
     * @param  string  $email
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    private function signIn(string $client, string $guard = 'api', string $email = 'ada@example.test'): SignedInSession
    {
        $session = $this->sessions($guard)->signIn('password', self::credentials($email), SignInContext::fromRequest(app('request'), clientName: $client))->session;

        self::assertNotNull($session);

        return $session;
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
     * Send a request with the session's access token.
     *
     * @param  string  $method
     * @param  string  $path
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignedInSession  $session
     * @param  array<string, mixed>  $body
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function send(string $method, string $path, SignedInSession $session, array $body = []): TestResponse
    {
        Auth::forgetGuards();

        return $this->withHeaders(['Authorization' => 'Bearer ' . $session->tokens->accessToken])->json($method, $path, $body);
    }
}
