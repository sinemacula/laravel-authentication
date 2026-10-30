<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Config\Repository as ConfigRepository;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Database\SharedConnection;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\SeparateConnectionCutoffIdentity;
use Tests\Integration\Fixtures\SeparateConnectionDevice;
use Tests\TestCase;

/**
 * Feature tests for the connection rule of the helpers that spend a proof with
 * a change to an identity and its sessions: an identity must live on the
 * storage connection, compared by name without opening one, and the provider's
 * model can be checked before any identity is found.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SharedConnection::class)]
final class SharedConnectionTest extends TestCase
{
    /**
     * An identity on the default connection shares it with the storage
     * connection, which names none either, or names the default one; an
     * identity on a named storage connection shares that.
     *
     * @return void
     */
    public function testAnIdentityOnTheStorageConnectionPasses(): void
    {
        self::assertNull(SharedConnection::mismatch(new IntegrationIdentity, self::config()));

        SharedConnection::assert(new IntegrationIdentity, 'A password reset', self::config());

        config()->set('authentication.storage.connection', 'testing');

        self::assertNull(SharedConnection::mismatch(new IntegrationIdentity, self::config()));

        config()->set('authentication.storage.connection', SeparateConnectionDevice::CONNECTION);

        $identity = (new IntegrationIdentity)->setConnection(SeparateConnectionDevice::CONNECTION);

        self::assertNull(SharedConnection::mismatch($identity, self::config()));
    }

    /**
     * An identity on another connection is refused, naming the flow, the model
     * and both connections, whatever connection the device model names.
     *
     * @return void
     */
    public function testAnIdentityOnAnotherConnectionIsRefused(): void
    {
        config()->set('authentication.storage.connection', SeparateConnectionDevice::CONNECTION);

        $expected = SeparateConnectionCutoffIdentity::class . ' must be on the storage connection (`authentication.storage.connection`):'
            . ' the identity is on [testing], the package\'s tables on [device_store].';

        self::assertSame($expected, SharedConnection::mismatch(new SeparateConnectionCutoffIdentity, self::config()));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('An identifier change spends its proof with its change to the identity in one transaction, so ' . $expected);

        SharedConnection::assert(new SeparateConnectionCutoffIdentity, 'An identifier change', self::config());
    }

    /**
     * The provider's model is the one its configuration names, as a new
     * instance; a provider that names none, or names a class that is not a
     * model, or a guard with no provider, gives none.
     *
     * @return void
     */
    public function testTheProvidersModelIsTheOneItsConfigurationNames(): void
    {
        config()->set('auth.providers.identities', ['driver' => 'model', 'model' => IntegrationIdentity::class]);
        config()->set('auth.providers.unnamed', ['driver' => 'custom']);
        config()->set('auth.providers.objects', ['driver' => 'model', 'model' => \stdClass::class]);
        config()->set('auth.guards.api', ['driver' => 'jwt', 'provider' => 'identities']);
        config()->set('auth.guards.custom', ['driver' => 'jwt', 'provider' => 'unnamed']);
        config()->set('auth.guards.objects', ['driver' => 'jwt', 'provider' => 'objects']);
        config()->set('auth.guards.orphan', ['driver' => 'jwt']);

        $model = SharedConnection::providerModel('api', self::config());

        self::assertInstanceOf(IntegrationIdentity::class, $model);
        self::assertFalse($model->exists);

        foreach (['custom', 'objects', 'orphan', 'missing'] as $guard) {
            self::assertNull(SharedConnection::providerModel($guard, self::config()), $guard);
        }
    }

    /**
     * `SharedConnection` is a utility container, not to be instantiated: its
     * constructor is private. Reflection invokes it so the line is covered
     * while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(SharedConnection::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(SharedConnection::class, $instance);
    }

    /**
     * The configuration.
     *
     * @return \Illuminate\Config\Repository
     */
    private static function config(): ConfigRepository
    {
        return app(ConfigRepository::class);
    }
}
