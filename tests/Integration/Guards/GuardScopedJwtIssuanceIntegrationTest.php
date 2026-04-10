<?php

declare(strict_types = 1);

namespace Tests\Integration\Guards;

use Carbon\Carbon;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use Illuminate\Database\Schema\Blueprint;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\TestCase;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Integration tests for guard-scoped JWT issuance.
 *
 * Verifies that `Auth::jwt('<guard>')` issues tokens that only authenticate
 * against the owning guard, and that refresh continues to issue follow-up
 * tokens under that same guard-local config.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversClass(JwtGuard::class)]
final class GuardScopedJwtIssuanceIntegrationTest extends TestCase
{
    /** @var string */
    private const string STAFF_GUARD = 'staff';

    /** @var string */
    private const string CUSTOMER_GUARD = 'customer';

    /** @var string */
    private const string STAFF_SECRET = 'staff-secret-with-at-least-32-bytes!!';

    /** @var string */
    private const string CUSTOMER_SECRET = 'customer-secret-with-32-bytes!!!!';

    /** @var \Carbon\Carbon */
    private Carbon $now;

    /**
     * Freeze the clock and create the in-memory identity table.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = Carbon::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Release the frozen clock and drop the in-memory schema.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        Schema::dropIfExists('stub_principals');

        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * Tokens issued through `Auth::jwt('<guard>')` authenticate only on their
     * owning guard when the guards carry distinct JWT secrets.
     *
     * @return void
     */
    public function testGuardScopedAccessTokensAuthenticateOnlyOnOwningGuard(): void
    {
        $principal = $this->seedPrincipal();

        $staffToken = PackageAuth::jwt(self::STAFF_GUARD)->issueAccessToken($principal, $principal, null);
        $customerToken = PackageAuth::jwt(self::CUSTOMER_GUARD)->issueAccessToken($principal, $principal, null);

        self::assertTrue($this->guardForBearer(self::STAFF_GUARD, $staffToken)->check());
        self::assertFalse($this->guardForBearer(self::CUSTOMER_GUARD, $staffToken)->check());

        self::assertTrue($this->guardForBearer(self::CUSTOMER_GUARD, $customerToken)->check());
        self::assertFalse($this->guardForBearer(self::STAFF_GUARD, $customerToken)->check());
    }

    /**
     * Refresh continues to issue follow-up credentials under the owning
     * guard's config, so a refreshed staff token still authenticates on the
     * staff guard and not on the customer guard.
     *
     * @return void
     */
    public function testRefreshIssuesFollowUpTokensThroughOwningGuardConfig(): void
    {
        $principal = $this->seedPrincipal();

        $plainRotationId = 'plain-rotation-id';

        $device = new Device;
        $device->forceFill([
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $principal->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'ios',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $refreshToken = PackageAuth::jwt(self::STAFF_GUARD)->issueRefreshToken($device, $plainRotationId);

        $staffGuard = $this->guard(self::STAFF_GUARD);
        $result = $staffGuard->refresh($refreshToken);

        self::assertInstanceOf(RefreshResult::class, $result);
        self::assertTrue($this->guardForBearer(self::STAFF_GUARD, $result->accessToken)->check());
        self::assertFalse($this->guardForBearer(self::CUSTOMER_GUARD, $result->accessToken)->check());
    }

    /**
     * Configure the two JWT guards with distinct secrets so the test can prove
     * guard-scoped issuance and verification.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        /** @var \Illuminate\Config\Repository $config */
        $config = $app->make(ConfigRepository::class);

        $config->set('auth.defaults.guard', self::STAFF_GUARD);

        $config->set('auth.guards.' . self::STAFF_GUARD, [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'secret'   => self::STAFF_SECRET,
                'audience' => 'staff-api',
            ],
        ]);

        $config->set('auth.guards.' . self::CUSTOMER_GUARD, [
            'driver'   => 'jwt',
            'provider' => 'identities',
            'jwt'      => [
                'secret'   => self::CUSTOMER_SECRET,
                'audience' => 'customer-api',
            ],
        ]);

        $config->set('auth.providers.identities', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);
    }

    /**
     * Persist and return an active principal used in 2D mode for both guards.
     *
     * @return \Tests\Unit\Stubs\StubPrincipal
     */
    private function seedPrincipal(): StubPrincipal
    {
        $principal = new StubPrincipal;
        $principal->email = 'guard-scoped@example.test';
        $principal->password = 'hashed-irrelevant';
        $principal->is_active = true;
        $principal->save();

        return $principal;
    }

    /**
     * Resolve a fresh guard for the current request.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guard(string $name): JwtGuard
    {
        PackageAuth::manager()->forgetGuards();

        $guard = PackageAuth::guard($name);

        assert($guard instanceof JwtGuard);

        return $guard;
    }

    /**
     * Resolve a fresh guard against a request carrying the supplied bearer
     * token.
     *
     * @param  string  $name
     * @param  string  $token
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function guardForBearer(string $name, #[\SensitiveParameter] string $token): JwtGuard
    {
        app()->instance('request', Request::create('/guard-scoped', 'GET', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer ' . $token,
        ]));

        return $this->guard($name);
    }
}
