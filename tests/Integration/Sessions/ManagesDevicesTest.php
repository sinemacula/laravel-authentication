<?php

declare(strict_types = 1);

namespace Tests\Integration\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Sessions\Concerns\ManagesDevices;
use Tests\Integration\Fixtures\CutoffIdentity;
use Tests\TestCase;

/**
 * End-to-end tests of signing out everywhere else from a session that has no
 * device: the request's own access-only token is kept by leaving the
 * identity's "tokens valid after" cutoff where it is, while every device is
 * revoked; without the keep, the cutoff ends that token too.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ManagesDevices::class)]
final class ManagesDevicesTest extends TestCase
{
    /** @var string The identity's password. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks, create the identity table and add the routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->moveClocksTo(CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0));

        Schema::create('cutoff_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->dateTime('tokens_valid_after', 0)->nullable();
            $blueprint->timestamps();
        });

        Route::middleware('auth:api')->group(static function (): void {

            Route::get('/me', static fn (): array => ['ok' => true]);

            Route::post('/logout-everywhere', static fn (Request $request): array => [
                'revoked' => Auth::sessions('api')->signOutEverywhere($request->boolean('keep')),
            ]);
        });
    }

    /**
     * Release the clocks and drop the identity table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Schema::dropIfExists('cutoff_identities');

        Carbon::setTestNow();
        CarbonImmutable::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * Keeping a device-less session leaves the cutoff where it is: the
     * request's token keeps working, as does the identity's other device-less
     * token, while its device is revoked.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testKeepingADevicelessSessionLeavesTheCutoff(): void
    {
        $identity = $this->seedIdentity();
        $device   = $this->signIn($identity);
        $current  = $this->tokens()->issueAccessToken($identity, $identity, null);
        $other    = $this->tokens()->issueAccessToken($identity, $identity, null);

        $this->moveClocksTo($this->now->addMinute());

        $this->bearer($current, 'POST', '/logout-everywhere', ['keep' => true])->assertOk()->assertJson(['revoked' => 1]);

        $this->bearer($current, 'GET', '/me')->assertOk();
        $this->bearer($other, 'GET', '/me')->assertOk();
        $this->bearer($device, 'GET', '/me')->assertUnauthorized();

        self::assertNull($identity->fresh()?->getTokensValidAfter());
        self::assertSame('signed_out_everywhere', DB::table('devices')->value('revoked_reason'));
    }

    /**
     * Without the keep, the cutoff moves and ends the request's device-less
     * token with the rest.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testSigningOutEverywhereEndsTheDevicelessSessionToo(): void
    {
        $identity = $this->seedIdentity();
        $current  = $this->tokens()->issueAccessToken($identity, $identity, null);

        $this->moveClocksTo($this->now->addMinute());

        $this->bearer($current, 'POST', '/logout-everywhere')->assertOk()->assertJson(['revoked' => 0]);

        $this->bearer($current, 'GET', '/me')->assertUnauthorized();

        self::assertSame($this->now->toDateTimeString(), $identity->fresh()?->getTokensValidAfter()?->toDateTimeString());
    }

    /**
     * Keeping a session that has a device keeps that device and still moves the
     * cutoff, which only device-less tokens are held to.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testKeepingADevicesSessionStillMovesTheCutoff(): void
    {
        $identity   = $this->seedIdentity();
        $current    = $this->signIn($identity);
        $other      = $this->signIn($identity);
        $deviceless = $this->tokens()->issueAccessToken($identity, $identity, null);

        $this->moveClocksTo($this->now->addMinute());

        $this->bearer($current, 'POST', '/logout-everywhere', ['keep' => true])->assertOk()->assertJson(['revoked' => 1]);

        $this->bearer($current, 'GET', '/me')->assertOk();
        $this->bearer($other, 'GET', '/me')->assertUnauthorized();
        $this->bearer($deviceless, 'GET', '/me')->assertUnauthorized();

        self::assertSame($this->now->toDateTimeString(), $identity->fresh()?->getTokensValidAfter()?->toDateTimeString());
    }

    /**
     * Configure the `api` guard over the identities that record a cutoff.
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

        $config->set('auth.providers.cutoff', ['driver' => 'model', 'model' => CutoffIdentity::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'cutoff', 'audience' => ['methods' => ['password', 'sso']]]);
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist an identity that records no cutoff yet.
     *
     * @return \Tests\Integration\Fixtures\CutoffIdentity
     */
    private function seedIdentity(): CutoffIdentity
    {
        $identity = new CutoffIdentity;
        $identity->forceFill(['email' => 'ada@example.test', 'password' => app(Hasher::class)->make(self::PASSWORD)])->save();

        return $identity;
    }

    /**
     * Sign the identity in on a new device and return the session's access
     * token.
     *
     * @param  \Tests\Integration\Fixtures\CutoffIdentity  $identity
     * @return string
     *
     * @throws \Throwable
     */
    private function signIn(CutoffIdentity $identity): string
    {
        Auth::forgetGuards();

        $session = Auth::sessions('api')->signIn('password', ['email' => $identity->email, 'password' => self::PASSWORD])->session;

        self::assertNotNull($session);

        return $session->tokens->accessToken;
    }

    /**
     * The `api` guard's token service.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function tokens(): JwtTokenService
    {
        $tokens = Auth::jwt('api');

        self::assertNotNull($tokens);

        return $tokens;
    }

    /**
     * Send a request with the bearer token.
     *
     * @param  string  $token
     * @param  string  $method
     * @param  string  $uri
     * @param  array<string, mixed>  $body
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(string $token, string $method, string $uri, array $body = []): TestResponse
    {
        Auth::forgetGuards();

        return $this->withHeaders(['Authorization' => 'Bearer ' . $token])->json($method, $uri, $body);
    }

    /**
     * Move every clock to the time.
     *
     * @param  \Carbon\CarbonImmutable  $time
     * @return void
     */
    private function moveClocksTo(CarbonImmutable $time): void
    {
        $this->now = $time;

        Carbon::setTestNow($time);
        CarbonImmutable::setTestNow($time);

        JWT::$timestamp = $time->getTimestamp();
    }
}
