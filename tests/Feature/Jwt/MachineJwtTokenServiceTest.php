<?php

declare(strict_types = 1);

namespace Tests\Feature\Jwt;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Exceptions\InvalidScopeException;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Jwt\MachineTokens;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Models\Device as DeviceModel;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;
use Tests\Unit\Stubs\StubBareDevice;

/**
 * Feature tests holding the token service to issuing no session token to a
 * non-human identity: no access token for one, and no refresh token for a
 * device one owns or for one as the principal, while human sessions are issued
 * as before.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtTokenService::class)]
#[CoversClass(MachineTokens::class)]
#[CoversClass(TokenLifetimes::class)]
final class MachineJwtTokenServiceTest extends TestCase
{
    /** @var string An API key id. */
    private const string KEY_ID = '0195f4a2-7b1c-7000-8000-000000000001';

    /** @var string The refusal every machine gets. */
    private const string REFUSAL = 'A non-human identity has no session: it gets access tokens only from a client credentials exchange.';

    /**
     * Freeze every clock the service reads.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        CarbonImmutable::setTestNow($now);
        Carbon::setTestNow($now);

        JWT::$timestamp = $now->getTimestamp();
    }

    /**
     * Release the clocks.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        CarbonImmutable::setTestNow();
        Carbon::setTestNow();

        JWT::$timestamp = null;

        parent::tearDown();
    }

    /**
     * No access token is issued to a machine, with or without a device.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssuesNoAccessTokenToAMachine(): void
    {
        $machine = self::machine();

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(self::REFUSAL);

        $this->tokens()->issueAccessToken($machine, $machine, null);
    }

    /**
     * No refresh token is issued for a device a machine owns, nor with a
     * machine as the principal; a human's device, plain or Eloquent, gets one.
     *
     * @return void
     */
    public function testIssuesNoRefreshTokenForAMachine(): void
    {
        $tokens  = $this->tokens();
        $machine = self::machine();
        $human   = self::device(IntegrationIdentity::class);

        foreach ([[self::device(MachineClient::class), null], [$human, $machine]] as [$device, $principal]) {
            try {
                $tokens->issueRefreshToken($device, 'rotation-id', $principal);

                self::fail('Expected the token service to refuse the machine.');
            } catch (\LogicException $exception) {
                self::assertSame(self::REFUSAL, $exception->getMessage());
            }
        }

        $plain = \Mockery::mock(Device::class);
        $plain->shouldReceive('getDeviceIdentifier')->andReturn('plain');
        $plain->shouldReceive('getIdleExpiresAt')->andReturn(CarbonImmutable::now()->addDay());
        $plain->shouldReceive('getAbsoluteExpiresAt')->andReturn(CarbonImmutable::now()->addDays(2));

        self::assertNotSame('', $tokens->issueRefreshToken($human, 'rotation-id', (new IntegrationIdentity)->forceFill(['id' => 7])));
        self::assertNotSame('', $tokens->issueRefreshToken($plain, 'rotation-id'));
    }

    /**
     * A device that is a model but not the package's Eloquent device records no
     * owner the service can read, so only its own state decides: here, its
     * missing deadlines.
     *
     * @return void
     */
    public function testAModelDeviceThatRecordsNoOwnerIsJudgedByItsState(): void
    {
        $device = (new StubBareDevice)->forceFill(['id' => 'bare']);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot issue a token for a device whose session has ended or that has no idle and absolute deadlines.');

        $this->tokens()->issueRefreshToken($device, 'rotation-id');
    }

    /**
     * A client token carries the access claims of its machine and principal, no
     * device, the key's id in `cid` and the scopes, space-separated, in
     * `scope`; it lives the guard's access lifetime, never past the time it is
     * bounded by.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testIssuesAClientToken(): void
    {
        $tokens  = $this->tokens();
        $machine = self::machine();
        $now     = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        $claims = $tokens->parse($tokens->issueClientAccessToken($machine, $machine, self::KEY_ID, ['read', 'write', 'read'], null, $now->addMilliseconds(400)));

        self::assertNotNull($claims);
        self::assertSame(self::KEY_ID, $claims[Claims::CREDENTIAL_ID->value]);
        self::assertSame('read write', $claims[Claims::SCOPE->value]);
        self::assertSame('7', $claims[Claims::SUBJECT->value]);
        self::assertSame('7', $claims[Claims::PRINCIPAL_ID->value]);
        self::assertNull($claims[Claims::DEVICE_ID->value]);
        self::assertSame('access', $claims[Claims::TYPE->value]);
        self::assertSame($now->getTimestamp(), $claims[Claims::ISSUED_AT->value]);
        self::assertSame($now->addMinutes(15)->getTimestamp(), $claims[Claims::EXPIRES_AT->value]);

        $bounded = $tokens->parse($tokens->issueClientAccessToken($machine, $machine, self::KEY_ID, [], $now->addMinutes(2), $now));

        self::assertNotNull($bounded);
        self::assertSame('', $bounded[Claims::SCOPE->value]);
        self::assertSame($now->addMinutes(2)->getTimestamp(), $bounded[Claims::EXPIRES_AT->value]);
    }

    /**
     * A client token is not issued past its bound, for a key id that is not a
     * UUID, or with a malformed scope.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testRefusesAClientTokenOutOfForm(): void
    {
        $tokens  = $this->tokens();
        $machine = self::machine();
        $now     = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        $pastBound = static fn (): string => $tokens->issueClientAccessToken($machine, $machine, self::KEY_ID, [], $now, $now->addMilliseconds(999));
        $notUuid   = static fn (): string => $tokens->issueClientAccessToken($machine, $machine, 'key-1', []);
        $refusals  = [
            'Cannot issue a token whose latest expiry is not after its issue time.'                           => $pastBound,
            'Cannot issue a client credentials token without its `cid` claim: the API key id must be a UUID.' => $notUuid,
        ];

        foreach ($refusals as $message => $issue) {
            try {
                $issue();

                self::fail("Expected: {$message}");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame($message, $exception->getMessage());
            }
        }

        $this->expectException(InvalidScopeException::class);

        $tokens->issueClientAccessToken($machine, $machine, self::KEY_ID, ['a b']);
    }

    /**
     * Rows of `[claims a forged token carries, accepted]`: a token with `cid`
     * must name a key by UUID, carry a scope string, and name no device.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool}>
     */
    public static function provideCredentialClaims(): iterable
    {
        yield from [
            'no credential'          => [[], true],
            'a credential and scope' => [['cid' => self::KEY_ID, 'scope' => 'read write'], true],
            'an empty scope'         => [['cid' => self::KEY_ID, 'scope' => ''], true],
            'a null credential'      => [['cid' => null, 'scope' => 'read'], true],
            'no scope'               => [['cid' => self::KEY_ID], false],
            'a scope list'           => [['cid' => self::KEY_ID, 'scope' => ['read']], false],
            'a malformed scope'      => [['cid' => self::KEY_ID, 'scope' => 'read  write'], false],
            'a key id not a uuid'    => [['cid' => 'key-1', 'scope' => ''], false],
            'a numeric key id'       => [['cid' => 7, 'scope' => ''], false],
            'a device'               => [['cid' => self::KEY_ID, 'scope' => '', 'did' => 'device-1'], false],
        ];
    }

    /**
     * `parse()` holds a token's credential claims to their form.
     *
     * @param  array<string, mixed>  $claims
     * @param  bool  $accepted
     * @return void
     */
    #[DataProvider('provideCredentialClaims')]
    public function testParseHoldsCredentialClaimsToTheirForm(array $claims, bool $accepted): void
    {
        $now     = CarbonImmutable::now()->getTimestamp();
        $payload = [
            'sub' => '7',
            'pid' => '7',
            'jti' => 'token-id',
            'iat' => $now,
            'exp' => $now + 60,
            'typ' => 'access',
            'grd' => 'api',
            ...$claims,
        ];

        $token = JWT::encode($payload, 'test-secret-key-with-at-least-32-bytes!', 'HS256', 'test-kid');

        self::assertSame($accepted, $this->tokens()->parse($token) !== null);
    }

    /**
     * The `api` guard's token service.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\JwtTokenService
     */
    private function tokens(): JwtTokenService
    {
        config()->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'users']);

        return Auth::manager()->jwt('api');
    }

    /**
     * An unsaved machine client with a key.
     *
     * @return \Tests\Integration\Fixtures\MachineClient
     */
    private static function machine(): MachineClient
    {
        return (new MachineClient)->forceFill(['id' => 7]);
    }

    /**
     * A live device row recording an owner of the class.
     *
     * @param  class-string  $owner
     * @return \SineMacula\Laravel\Authentication\Models\Device
     */
    private static function device(string $owner): DeviceModel
    {
        return (new DeviceModel)->forceFill([
            'id'                   => 'device-1',
            'authenticatable_type' => $owner,
            'authenticatable_id'   => '7',
            'idle_expires_at'      => CarbonImmutable::now()->addDay(),
            'absolute_expires_at'  => CarbonImmutable::now()->addDays(2),
        ]);
    }
}
