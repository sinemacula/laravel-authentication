<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Device as DeviceContract;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn;
use SineMacula\Laravel\Authentication\Sessions\DeviceProof;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Feature tests for what proves a client holds a device: its current refresh
 * token, validly signed for the guard and possibly expired, for a device of the
 * guard that the identity signing in owns, for the same principal, and that is
 * not revoked. Anything less proves nothing.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeviceProof::class)]
final class DeviceProofTest extends TestCase
{
    use InteractsWithSessions;

    /** @var \Tests\Integration\Fixtures\IntegrationIdentity The identity whose device is proven. */
    private IntegrationIdentity $identity;

    /** @var \SineMacula\Laravel\Authentication\Sessions\SignedInSession The session whose device is proven. */
    private SignedInSession $session;

    /**
     * Freeze the clocks, create the tables, and start a session to prove.
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

        $this->identity = $this->seedIdentity();

        $session = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        $this->session = $session;
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
     * The current refresh token proves its device, live or expired.
     *
     * @return void
     */
    public function testTheCurrentRefreshTokenProvesItsDevice(): void
    {
        $proven = $this->prove($this->session->tokens->refreshToken);

        self::assertInstanceOf(Device::class, $proven);
        self::assertSame($this->session->device->getKey(), $proven->getKey());

        JWT::$timestamp = Carbon::now()->addYears(2)->getTimestamp();

        self::assertSame($this->session->device->getKey(), $this->prove($this->session->tokens->refreshToken)?->getDeviceIdentifier());
    }

    /**
     * A device that is revoked, holds no refresh credential, or holds another
     * rotation id is not proven.
     *
     * @return void
     */
    public function testTheDeviceMustBeLiveAndHoldTheRotationId(): void
    {
        $token = $this->session->tokens->refreshToken;

        $this->updateDevice(['refresh_key' => hash('sha256', 'another-rotation-id')]);
        self::assertNull($this->prove($token));

        $this->updateDevice(['refresh_key' => null]);
        self::assertNull($this->prove($token));

        $this->updateDevice(['refresh_key' => hash('sha256', (string) $this->claims($token)[Claims::JWT_ID->value]), 'revoked_at' => Carbon::now()]); // @phpstan-ignore cast.string
        self::assertNull($this->prove($token));

        $this->updateDevice(['revoked_at' => null]);
        self::assertNotNull($this->prove($token));
    }

    /**
     * The device must be the identity's own, record the guard proving it, and
     * record the principal signing in.
     *
     * @return void
     */
    public function testTheDeviceMustBeTheIdentitysForTheGuardAndPrincipal(): void
    {
        $token = $this->session->tokens->refreshToken;
        $other = $this->seedIdentity('bea@example.test');

        self::assertNull($this->prove($token, $other));
        self::assertNull((new DeviceProof(Auth::manager()->jwt('api')))->provenDevice('admin', $this->admitted($this->identity), $token));

        $this->updateDevice(['guard' => 'admin']);
        self::assertNull($this->prove($token));

        $this->updateDevice(['guard' => 'api']);

        [$member, $membership] = $this->seedMember();

        self::assertNull($this->prove($token, $this->identity, $membership));
        self::assertNull($this->prove($token, $member, $membership));
        self::assertNotNull($this->prove($token));
    }

    /**
     * Only a refresh token of this guard naming an existing device is a proof:
     * garbage, an access token, another guard's refresh token, and one naming
     * no device prove nothing.
     *
     * @return void
     */
    public function testOnlyARefreshTokenOfTheGuardNamingADeviceIsAProof(): void
    {
        $admin = Auth::manager()->jwt('admin');
        $api   = Auth::manager()->jwt('api');

        $claims = $this->claims($this->session->tokens->refreshToken);

        self::assertNull($this->prove('not-a-jwt'));
        self::assertNull($this->prove($this->session->tokens->accessToken));
        self::assertNull($this->prove($admin->issueRefreshToken($this->session->device, (string) $claims[Claims::JWT_ID->value], $this->identity))); // @phpstan-ignore cast.string

        $this->session->device->delete();

        self::assertNull($this->prove($api->issueRefreshToken($this->session->device, (string) $claims[Claims::JWT_ID->value], $this->identity))); // @phpstan-ignore cast.string
    }

    /**
     * A refresh token whose rotation id is not a string proves nothing, even
     * when it is validly signed.
     *
     * @return void
     */
    public function testARotationIdThatIsNotAStringProvesNothing(): void
    {
        $claims = $this->claims($this->session->tokens->refreshToken);

        $claims[Claims::JWT_ID->value] = 12345;

        self::assertNull($this->prove(JWT::encode($claims, 'test-secret-key-with-at-least-32-bytes!', 'HS256', 'test-kid')));
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
     * Ask the `api` guard's proof for the device the token proves for the
     * identity (the seeded one by default) acting as the principal (itself by
     * default).
     *
     * @param  string  $token
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Device
     */
    private function prove(#[\SensitiveParameter] string $token, ?Identity $identity = null, ?Principal $principal = null): ?DeviceContract
    {
        return (new DeviceProof(Auth::manager()->jwt('api')))->provenDevice('api', $this->admitted($identity ?? $this->identity, $principal), $token);
    }

    /**
     * An admitted sign-in of the identity as the principal (itself by default).
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn
     */
    private function admitted(Identity $identity, ?Principal $principal = null): AdmittedSignIn
    {
        self::assertTrue($principal !== null || $identity instanceof Principal);

        /** @var \SineMacula\Laravel\Authentication\Contracts\Principal $acting */
        $acting = $principal ?? $identity;

        return new AdmittedSignIn($identity, $acting, null);
    }

    /**
     * The claims of the token, accepting an expired one.
     *
     * @param  string  $token
     * @return array<string, mixed>
     */
    private function claims(#[\SensitiveParameter] string $token): array
    {
        $claims = Auth::manager()->jwt('api')->parse($token, TokenType::REFRESH);

        self::assertIsArray($claims);

        return $claims;
    }

    /**
     * Write values onto the session's device row.
     *
     * @param  array<string, mixed>  $values
     * @return void
     */
    private function updateDevice(array $values): void
    {
        Device::query()->whereKey($this->session->device->getKey())->update($values);
    }
}
