<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Carbon\CarbonImmutable;
use Firebase\JWT\JWT;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Foundation\Application;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\Enums\TokenType;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Jwt\TokenLifetimes;
use SineMacula\Laravel\Authentication\Models\Device;
use SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn;
use SineMacula\Laravel\Authentication\Sessions\SessionWriter;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\TestCase;

/**
 * Feature tests for writing a session: creating a device, and continuing a
 * proven one with a compare-and-swap that applies only to the row as it was
 * proven.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionWriter::class)]
final class SessionWriterTest extends TestCase
{
    use InteractsWithSessions;

    /** @var \Carbon\CarbonImmutable Frozen clock reference. */
    private CarbonImmutable $now;

    /**
     * Freeze the clocks and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->now = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);

        Carbon::setTestNow($this->now);
        CarbonImmutable::setTestNow($this->now);

        JWT::$timestamp = $this->now->getTimestamp();

        $this->createSessionTables();
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
     * A new device records the sign-in and is issued a pair at `$now` whose
     * refresh token carries the rotation id the device stores the digest of.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCreateWritesTheDeviceAndIssuesItsPair(): void
    {
        $identity = $this->seedIdentity();
        $session  = $this->writer()->create('api', $this->admitted($identity), 'password', $this->context('Laptop', 'macOS'), $this->lifetimes(), $this->now);
        $device   = Device::query()->whereKey($session->device->getKey())->firstOrFail();
        $claims   = Auth::manager()->jwt('api')->parse($session->tokens->refreshToken, TokenType::REFRESH);

        self::assertTrue($session->deviceCreated);
        self::assertSame('password', $session->method);
        self::assertNotNull($claims);
        self::assertSame($this->now->getTimestamp(), $claims['iat']);
        self::assertTrue(RefreshTokenHasher::verify((string) $claims['jti'], (string) $device->getRefreshKey())); // @phpstan-ignore cast.string
        self::assertSame('Laptop', $device->client_name);
        self::assertSame('macOS', $device->platform);
        self::assertSame('192.0.2.1', $device->created_ip);
        self::assertSame('Writer/1.0', $device->created_user_agent);
        self::assertSame($this->now->addMinutes(60)->getTimestamp(), $device->getIdleExpiresAt()?->getTimestamp());
        self::assertSame($this->now->addMinutes(120)->getTimestamp(), $device->getAbsoluteExpiresAt()?->getTimestamp());
    }

    /**
     * A device can only be owned by an Eloquent identity; anything else is a
     * misconfiguration and writes nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCreateRefusesAnIdentityThatIsNotAModel(): void
    {
        $identity  = \Mockery::mock(Identity::class);
        $principal = \Mockery::mock(Principal::class);

        try {
            $this->writer()->create('api', new AdmittedSignIn($identity, $principal, null), 'password', $this->context(), $this->lifetimes(), $this->now);
            self::fail('Expected an identity that is not a model to be refused.');
        } catch (\LogicException $exception) {
            self::assertSame(sprintf('The session service can only create a device for an Eloquent identity; %s is not a model.', $identity::class), $exception->getMessage());
        }

        self::assertSame(0, Device::query()->count());
    }

    /**
     * Continuing a proven device swaps in a new session and mirrors it on the
     * in-memory device as persisted; a client description the context does not
     * give is kept.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testContinueOnSwapsInANewSessionAndMirrorsIt(): void
    {
        $identity = $this->seedIdentity();
        $first    = $this->writer()->create('api', $this->admitted($identity), 'password', $this->context('Laptop', 'macOS'), $this->lifetimes(), $this->now);
        $proven   = Device::query()->whereKey($first->device->getKey())->firstOrFail();

        $later = $this->now->addHour();

        $again = $this->writer()->continueOn($proven, $this->admitted($identity)->on($proven), 'sso', $this->context(null, 'Linux'), $this->lifetimes(), $later);

        self::assertNotNull($again);
        self::assertSame($proven, $again->device);
        self::assertFalse($again->deviceCreated);
        self::assertFalse($proven->isDirty());

        $row = Device::query()->whereKey($proven->getKey())->firstOrFail();

        foreach ([$proven, $row] as $device) {
            self::assertSame('sso', $device->getSignInMethod());
            self::assertSame('Laptop', $device->client_name);
            self::assertSame('Linux', $device->platform);
            self::assertSame($later->getTimestamp(), $device->getLastUsedAt()?->getTimestamp());
            self::assertSame($later->addMinutes(120)->getTimestamp(), $device->getAbsoluteExpiresAt()?->getTimestamp());
            self::assertNotSame($first->device->getRefreshKey(), $device->getRefreshKey());
        }
    }

    /**
     * Rows of `[change]`: what changed on the row after it was proven.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideChangesSinceTheProof(): iterable
    {
        yield from [
            'rotated'           => [['refresh_key' => RefreshTokenHasher::hash('rotated')]],
            'revoked'           => [['revoked_at' => '2026-04-06 12:30:00']],
            'another owner'     => [['authenticatable_id' => '999']],
            'another principal' => [['principal_id' => '999']],
        ];
    }

    /**
     * A row that changed after it was proven is not continued: the swap misses,
     * nothing is written or issued, and the in-memory device keeps its state.
     *
     * @param  array<string, mixed>  $change
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideChangesSinceTheProof')]
    public function testContinueOnMissesARowThatChangedSinceItWasProven(array $change): void
    {
        $identity = $this->seedIdentity();
        $first    = $this->writer()->create('api', $this->admitted($identity), 'password', $this->context(), $this->lifetimes(), $this->now);
        $proven   = Device::query()->whereKey($first->device->getKey())->firstOrFail();

        Device::query()->whereKey($proven->getKey())->update($change);

        $before = (array) Device::query()->whereKey($proven->getKey())->toBase()->first();
        $digest = $proven->getRefreshKey();

        self::assertNull($this->writer()->continueOn($proven, $this->admitted($identity)->on($proven), 'sso', $this->context('New'), $this->lifetimes(), $this->now->addHour()));
        self::assertSame($before, (array) Device::query()->whereKey($proven->getKey())->toBase()->first());
        self::assertSame($digest, $proven->getRefreshKey());
        self::assertSame('password', $proven->getSignInMethod());
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
     * The writer for the `api` guard.
     *
     * @return \SineMacula\Laravel\Authentication\Sessions\SessionWriter
     */
    private function writer(): SessionWriter
    {
        return new SessionWriter(Auth::manager()->jwt('api'), app(ConnectionResolverInterface::class));
    }

    /**
     * An admitted 2D sign-in of the identity.
     *
     * @param  \Tests\Integration\Fixtures\IntegrationIdentity  $identity
     * @return \SineMacula\Laravel\Authentication\Sessions\Admission\AdmittedSignIn
     */
    private function admitted(IntegrationIdentity $identity): AdmittedSignIn
    {
        return new AdmittedSignIn($identity, $identity, null);
    }

    /**
     * A sign-in context from a known client.
     *
     * @param  ?string  $clientName
     * @param  ?string  $platform
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInContext
     */
    private function context(?string $clientName = null, ?string $platform = null): SignInContext
    {
        return new SignInContext(new ClientContext('192.0.2.1', 'Writer/1.0'), $clientName, $platform);
    }

    /**
     * Lifetimes of an hour idle and two hours absolute.
     *
     * @return \SineMacula\Laravel\Authentication\Jwt\TokenLifetimes
     */
    private function lifetimes(): TokenLifetimes
    {
        return new TokenLifetimes(5, 60, 120, 30);
    }
}
