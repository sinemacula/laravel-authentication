<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Database\Events\QueryExecuted;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Sessions\IdentityDevices;
use Tests\Concerns\InteractsWithSessions;
use Tests\TestCase;

/**
 * Feature tests of finding one of an identity's devices by its identifier, on
 * the write connection, through the identity's own relation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentityDevices::class)]
final class IdentityDevicesTest extends TestCase
{
    use InteractsWithSessions;

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
     * The identity's own device is found by its identifier; another identity's
     * device is not.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testFindsOnlyTheIdentitysOwnDevice(): void
    {
        $identity = $this->seedIdentity();
        $other    = $this->seedIdentity('grace@example.test');
        $session  = $this->sessions()->signIn('password', self::credentials())->session;

        self::assertNotNull($session);

        $id = $session->device->getDeviceIdentifier();

        self::assertSame($id, IdentityDevices::find($identity, $id)?->getDeviceIdentifier());
        self::assertNull(IdentityDevices::find($other, $id));
    }

    /**
     * An identifier that cannot be a key of the device model is not found,
     * without a query, and an identity that holds no devices has none.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnIdentifierThatCannotBeAKeyIsNotLookedUp(): void
    {
        $identity = $this->seedIdentity();
        $queries  = 0;

        DB::listen(static function (QueryExecuted $query) use (&$queries): void {
            $queries++;
        });

        self::assertNull(IdentityDevices::find($identity, 'not-a-uuid'));
        self::assertNull(IdentityDevices::find($identity, ['0190e1a4-0000-7000-8000-000000000000']));
        self::assertNull(IdentityDevices::find(\Mockery::mock(Identity::class, Principal::class), '0190e1a4-0000-7000-8000-000000000000'));
        self::assertSame(0, $queries);
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
}
