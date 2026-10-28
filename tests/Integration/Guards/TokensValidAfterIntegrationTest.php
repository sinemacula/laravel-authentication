<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Route;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Events\AuthenticationFailed;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Guards\BearerAuthentication;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use Tests\Integration\Fixtures\CutoffIdentity;
use Tests\TestCase;

/**
 * End-to-end tests for "tokens valid after" against a real database: an access
 * token issued without a device stops at the second the identity's time is
 * moved to, while the tokens of its signed-in devices, which revocation
 * governs, keep working.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(BearerAuthentication::class)]
final class TokensValidAfterIntegrationTest extends TestCase
{
    /** @var string The identity's password. */
    private const string PASSWORD = 'correct horse battery staple';

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /** @var list<\SineMacula\Laravel\Authentication\Events\Enums\FailureReason> The reasons of the rejected tokens. */
    private array $reasons = [];

    /**
     * Freeze the clocks, create the identity table, record the bearer failures,
     * and add a route behind the `auth` middleware.
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

        Event::listen(AuthenticationFailed::class, function (AuthenticationFailed $event): void {
            $this->reasons[] = $event->reason;
        });

        Route::middleware('auth:api')->get('/me', static fn (): array => ['device' => Auth::device()?->getDeviceIdentifier()]);
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
     * Moving the time ends every device-less token issued up to and including
     * its second; a token issued in the next second works.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testATimeEndsTheDevicelessTokensIssuedUpToItsSecond(): void
    {
        $identity = $this->seedIdentity();
        $earlier  = $this->tokens()->issueAccessToken($identity, $identity, null);

        $this->moveClocksTo($this->now->addMinute());

        $current = $this->tokens()->issueAccessToken($identity, $identity, null);

        $this->bearer($earlier)->assertOk();

        self::assertTrue($identity->invalidateTokensIssuedBefore($this->now));

        $this->bearer($earlier)->assertUnauthorized();
        $this->bearer($current)->assertUnauthorized();

        $this->moveClocksTo($this->now->addSecond());

        $this->bearer($this->tokens()->issueAccessToken($identity, $identity, null))->assertOk();

        self::assertSame([FailureReason::ISSUED_BEFORE_CUTOFF, FailureReason::ISSUED_BEFORE_CUTOFF], $this->reasons);
    }

    /**
     * A signed-in device's access token is not held to the time: revoking the
     * device ends it, and a sign-out everywhere that keeps the current device
     * must leave that device's token working.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testADevicesTokenIsNotHeldToTheTime(): void
    {
        $identity = $this->seedIdentity();
        $session  = Auth::sessions('api')->signIn('password', ['email' => $identity->email, 'password' => self::PASSWORD])->session;

        self::assertNotNull($session);

        $identity->invalidateTokensIssuedBefore($this->now->addMinute());

        $this->bearer($session->tokens->accessToken)->assertOk()->assertJson(['device' => $session->device->getKey()]);

        self::assertSame([], $this->reasons);
    }

    /**
     * An identity that records no time does not limit its tokens.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testNoTimeLeavesTheTokensValid(): void
    {
        $identity = $this->seedIdentity();

        $this->bearer($this->tokens()->issueAccessToken($identity, $identity, null))->assertOk();

        self::assertSame([], $this->reasons);
    }

    /**
     * Configure the `api` guard over the identities that record a time.
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

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.providers.cutoff', ['driver' => 'model', 'model' => CutoffIdentity::class]);
        $config->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'cutoff']);
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist an identity that records no time yet.
     *
     * @return \Tests\Integration\Fixtures\CutoffIdentity
     */
    private function seedIdentity(): CutoffIdentity
    {
        $identity           = new CutoffIdentity;
        $identity->email    = 'ada@example.test';
        $identity->password = app(Hasher::class)->make(self::PASSWORD);
        $identity->save();

        return $identity;
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
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(string $token): TestResponse
    {
        Auth::forgetGuards();

        return $this->withHeaders(['Authorization' => 'Bearer ' . $token])->getJson('/me');
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
