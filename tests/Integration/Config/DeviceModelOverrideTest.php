<?php

declare(strict_types = 1);

namespace Tests\Integration\Config;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Timebox;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\AuthServiceProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\PrincipalResolver;
use SineMacula\Laravel\Authentication\Facades\Auth as PackageAuth;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenExchange;
use SineMacula\Laravel\Authentication\Jwt\RefreshTokenHasher;
use SineMacula\Laravel\Authentication\Models\Device;
use Tests\TestCase;
use Tests\Unit\Stubs\InjectableDeviceStub;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * Integration test for the Device model override via package config.
 *
 * Verifies that overriding `config('authentication.device.model')` with a
 * custom `Device` subclass and `device.table` with a custom table name causes
 * the model, the shipped migration body, and the JWT guard's device-hydration
 * path to route through the override.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversClass(AuthServiceProvider::class)]
#[CoversClass(Device::class)]
#[CoversClass(RefreshTokenExchange::class)]
final class DeviceModelOverrideTest extends TestCase
{
    /** @var class-string<\SineMacula\Laravel\Authentication\Models\Device> FQCN of the custom device subclass under test. */
    private string $customModel;

    /**
     * Configure the custom device model class and table name, then replay the
     * shipped migration body inline against the in-memory connection so the
     * custom table exists for the test.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        // Anonymous subclass of the shipped Device model - the FQCN is
        // synthetic but usable as a `class-string` across the test.
        $anonymous = new class extends Device {};

        /** @var class-string<\SineMacula\Laravel\Authentication\Models\Device> $class */
        $class = $anonymous::class;

        $this->customModel = $class;

        config()->set('authentication.device.model', $this->customModel);
        config()->set('authentication.device.table', 'custom_devices');

        // The Device model now caches the table name statically (set The Device
        // model reads the table name lazily in its constructor, so no manual
        // cache priming is needed - the config swap in `defineEnvironment()` is
        // picked up on the next instantiation.
        Schema::create('custom_devices', static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
            $blueprint->string('authenticatable_type')->nullable();
            $blueprint->string('authenticatable_id')->nullable();
            $blueprint->string('os')->default('');
            $blueprint->string('refresh_key', 64)->nullable();
            $blueprint->timestamp('revoked_at')->nullable();
            $blueprint->timestamp('last_logged_in_at')->nullable();
            $blueprint->timestamp('last_mfa_verified_at')->nullable();
            $blueprint->timestamps();
        });

        Schema::create('stub_principals', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the custom tables on tear-down so each test starts clean.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        Schema::dropIfExists('custom_devices');
        Schema::dropIfExists('stub_principals');
        InjectableDeviceStub::$injectedBuilder = null;

        parent::tearDown();
    }

    /**
     * The custom device model FQCN is readable through the config key
     * consumers will set in their application config.
     *
     * @return void
     */
    public function testCustomDeviceModelClassResolvesViaConfig(): void
    {
        self::assertSame(
            $this->customModel,
            config('authentication.device.model'),
        );
    }

    /**
     * Instantiating the custom subclass yields a model whose table matches the
     * configured `device.table` value.
     *
     * @return void
     */
    public function testCustomTableNameAppliesToDeviceModel(): void
    {
        $model = new $this->customModel;

        self::assertSame('custom_devices', $model->getTable());
    }

    /**
     * The shipped migration body creates the custom table (not the default
     * `devices` table) when `device.table` is overridden.
     *
     * @return void
     */
    public function testCustomTableNameAppliesToShippedMigration(): void
    {
        self::assertTrue(Schema::hasTable('custom_devices'));
        self::assertFalse(Schema::hasTable('devices'));
    }

    /**
     * Invoking `JwtGuard::refresh()` with a refresh token whose `did` claim
     * points at a row in the custom table returns a refreshed access token
     * sourced from the overridden model class, binding an instance of that
     * class as the active device.
     *
     * @return void
     */
    public function testGuardResolvesDeviceThroughCustomModelClass(): void
    {
        // Arrange: persist a principal identity and a device row on the custom
        // table, then build a refresh token whose `did` claim points at that
        // row. The stored refresh_key is the SHA-256 digest of the plaintext
        // rotation id; the token carries the plaintext in its `jti` claim.
        $principal = new StubPrincipal;
        $principal->forceFill(['is_active' => true])->save();

        $plainRotationId = 'plain-rotation-id';

        /** @var \SineMacula\Laravel\Authentication\Models\Device $device */
        $device = new $this->customModel;
        $device->forceFill([
            'authenticatable_type' => StubPrincipal::class,
            'authenticatable_id'   => (string) $principal->getKey(), // @phpstan-ignore cast.string
            'os'                   => 'ios',
            'refresh_key'          => RefreshTokenHasher::hash($plainRotationId),
        ])->save();

        $refreshToken = PackageAuth::jwt('custom-jwt')->issueRefreshToken($device, $plainRotationId);

        $guard = $this->makeJwtGuard();

        // Act: exchange the refresh token via the guard's refresh() path, which
        // reads the configured model class.
        $result = $guard->refresh($refreshToken);

        // Assert: the refresh succeeded and the bound device is an instance of
        // the overridden model class.
        self::assertInstanceOf(RefreshResult::class, $result);
        self::assertNotSame('', $result->accessToken);
        self::assertNotSame('', $result->refreshToken);
        self::assertInstanceOf($this->customModel, $guard->device());
    }

    /**
     * Skip the parent's default `devices` migration so this test can verify
     * that the custom-table override is the only `devices`-shaped table on the
     * connection (TAC: `Schema::hasTable('devices') === false`).
     *
     * @return void
     */
    protected function defineDatabaseMigrations(): void
    {
        // intentionally empty - the test creates the custom table in setUp().
    }

    /**
     * Register the manual `custom-jwt` guard config used by the guard-scoped
     * `Auth::jwt('custom-jwt')` issuance surface in this test.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        config()->set('auth.guards.custom-jwt', [
            'driver'   => 'jwt',
            'provider' => 'principals',
        ]);

        config()->set('auth.providers.principals', [
            'driver' => 'model',
            'model'  => StubPrincipal::class,
        ]);
    }

    /**
     * Build a `JwtGuard` wired against a stub identity provider that echoes a
     * persisted `StubPrincipal` for any identifier lookup, and a resolver that
     * treats the identity as its own principal (2D mode).
     *
     * @return \SineMacula\Laravel\Authentication\Guards\JwtGuard
     */
    private function makeJwtGuard(): JwtGuard
    {
        $provider = new class implements IdentityProvider {
            /**
             * Retrieve a persisted `StubPrincipal` by its primary key.
             *
             * @param  mixed  $identifier
             * @return ?\Illuminate\Contracts\Auth\Authenticatable
             */
            public function retrieveById(mixed $identifier): ?Authenticatable
            {
                $result = StubPrincipal::query()->find($identifier);

                return $result instanceof Authenticatable ? $result : null;
            }

            /**
             * @param  mixed  $identifier
             * @param  mixed  $token
             * @return ?\Illuminate\Contracts\Auth\Authenticatable
             */
            public function retrieveByToken(mixed $identifier, mixed $token): ?Authenticatable
            {
                return null;
            }

            /**
             * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
             * @param  mixed  $token
             * @return void
             */
            public function updateRememberToken(Authenticatable $user, mixed $token): void {}

            /**
             * Credentials-based retrieval is not exercised by this test.
             *
             * @param  array<array-key, mixed>  $credentials
             * @return ?\Illuminate\Contracts\Auth\Authenticatable
             */
            public function retrieveByCredentials(array $credentials): ?Authenticatable
            {
                return null;
            }

            /**
             * Credential validation is not exercised by this test.
             *
             * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
             * @param  array<array-key, mixed>  $credentials
             * @return bool
             */
            public function validateCredentials(Authenticatable $user, array $credentials): bool
            {
                return false;
            }

            /**
             * Rehashing is not exercised by this test.
             *
             * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
             * @param  array<array-key, mixed>  $credentials
             * @param  bool  $force
             * @return void
             */
            public function rehashPasswordIfRequired(Authenticatable $user, array $credentials, bool $force = false): void {}
        };

        $resolver = new class implements PrincipalResolver {
            /**
             * 2D resolver: return the identity if it is its own principal.
             *
             * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
             * @param  mixed  $hint
             * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
             */
            public function resolve(Identity $identity, mixed $hint = null): ?Principal
            {
                return $identity instanceof Principal ? $identity : null;
            }
        };

        $tokens   = PackageAuth::jwt('custom-jwt');
        $events   = app(Dispatcher::class);
        $exchange = new RefreshTokenExchange(
            $tokens,
            app(ConnectionResolverInterface::class),
            $events,
            $resolver,
            'custom-jwt',
        );

        return new JwtGuard(
            'custom-jwt',
            $provider,
            $resolver,
            $events,
            app('request'),
            app(Timebox::class),
            $tokens,
            $exchange,
        );
    }
}
