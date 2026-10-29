<?php

declare(strict_types = 1);

namespace Tests\Feature\Passkeys;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\IdentityProvider;
use SineMacula\Laravel\Authentication\Models\Passkey;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyOwner;
use Tests\Concerns\InteractsWithMachineClients;
use Tests\Concerns\InteractsWithPasskeys;
use Tests\Concerns\InteractsWithSessions;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\MachineClient;
use Tests\TestCase;

/**
 * Feature tests for who may own a passkey and how its owner is recorded and
 * found again: a saved Eloquent identity that is not a machine identity,
 * recorded by its morph class and key, and reloaded through a guard's provider
 * only as that very model.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyOwner::class)]
final class PasskeyOwnerTest extends TestCase
{
    use InteractsWithMachineClients, InteractsWithPasskeys, InteractsWithSessions;

    /**
     * Create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createSessionTables();

        self::createMachineClientsTable();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropMachineClientsTable();

        $this->dropSessionTables();

        parent::tearDown();
    }

    /**
     * An Eloquent identity that is not a machine identity may own passkeys, as
     * itself.
     *
     * @return void
     */
    public function testAnEloquentIdentityMayOwnPasskeys(): void
    {
        $identity = $this->seedIdentity();

        self::assertSame($identity, PasskeyOwner::of($identity));
    }

    /**
     * A machine identity is refused as a misconfiguration: it has no
     * interactive sign-in.
     *
     * @return void
     */
    public function testAMachineIdentityIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(MachineClient::class . ' is a machine identity, which signs in with no passkey.');

        PasskeyOwner::of(MachineClient::query()->create(['email' => 'robot@example.test']));
    }

    /**
     * An identity that is not an Eloquent model cannot be recorded as an owner.
     *
     * @return void
     */
    public function testAnIdentityThatIsNotAModelIsRefused(): void
    {
        $identity = \Mockery::mock(Identity::class);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Passkeys can only belong to an Eloquent identity; ' . $identity::class . ' is not a model.');

        PasskeyOwner::of($identity);
    }

    /**
     * The owner is recorded by its morph class and its key as a string, and a
     * passkey is owned only by the model with both: not one of another class
     * under the key, and not another key.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheOwnerIsRecordedByItsTypeAndKey(): void
    {
        $identity = $this->seedIdentity();
        [$member] = $this->seedMember();

        self::assertSame([IntegrationIdentity::class, (string) $identity->id], PasskeyOwner::columns($identity));

        $this->registerPasskey($identity);

        $passkey = Passkey::query()->sole();

        self::assertTrue(PasskeyOwner::owns($identity, $passkey));
        self::assertFalse(PasskeyOwner::owns($member, $passkey));
        self::assertFalse(PasskeyOwner::owns($this->seedIdentity('grace@example.test'), $passkey));
    }

    /**
     * An identity without a key, not saved yet, cannot be recorded.
     *
     * @return void
     */
    public function testAnUnsavedIdentityCannotBeRecorded(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage(IntegrationIdentity::class . ' must be saved before it can hold passkeys.');

        PasskeyOwner::columns(new IntegrationIdentity);
    }

    /**
     * The owner reloads through the guard's provider only as the very model the
     * passkey records: not another identity, not an identity that is not a
     * model, and not nothing.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testTheOwnerReloadsOnlyAsTheModelThePasskeyRecords(): void
    {
        $identity = $this->seedIdentity();

        $this->registerPasskey($identity);

        $passkey  = Passkey::query()->sole();
        $other    = $this->seedIdentity('grace@example.test');
        $provider = \Mockery::mock(IdentityProvider::class);

        $provider->shouldReceive('retrieveById')->with((string) $identity->id)->andReturn($identity, $other, \Mockery::mock(Identity::class), null);

        self::assertSame($identity, PasskeyOwner::load($passkey, $provider));
        self::assertNull(PasskeyOwner::load($passkey, $provider));
        self::assertNull(PasskeyOwner::load($passkey, $provider));
        self::assertNull(PasskeyOwner::load($passkey, $provider));
    }

    /**
     * `PasskeyOwner` is a static utility; instantiation is disallowed via the
     * private constructor. Reflection invokes it so the line is covered while
     * still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(PasskeyOwner::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(PasskeyOwner::class, $instance);
    }

    /**
     * Configure the guards and their relying party.
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

        self::configureSessionGuards($config);
        self::configurePasskeys($config);
    }
}
