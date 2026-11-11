<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions\Methods;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\OtherDeviceLogout;
use Illuminate\Auth\Events\Validated;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Hash;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Sessions\Methods\Rehashing;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\VerifiableIdentity;
use Tests\Integration\Fixtures\VerifiableStaffIdentity;
use Tests\TestCase;

/**
 * Feature tests of how the rehash mark tells Eloquent users apart by their
 * stored row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Rehashing::class)]
final class RehashingAccountsTest extends TestCase
{
    /** @var string The password the attempts are made with. */
    private const string PASSWORD = 'secret';

    /**
     * Rows of a user with the attempt's class and key, stored elsewhere.
     *
     * @return iterable<string, array{0: \Closure(): (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity)}>
     */
    public static function provideTheSameKeyElsewhere(): iterable
    {
        yield 'on another connection' => [static fn (): IntegrationIdentity => (new IntegrationIdentity)->setConnection('elsewhere')];
        yield 'in another table' => [static fn (): IntegrationIdentity => (new IntegrationIdentity)->setConnection('tenant')->setTable('other_identities')];
    }

    /**
     * The same class and key stored elsewhere is another user.
     *
     * @param  \Closure(): (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity)  $elsewhere
     * @return void
     */
    #[DataProvider('provideTheSameKeyElsewhere')]
    public function testTheSameKeyElsewhereIsAnotherUser(\Closure $elsewhere): void
    {
        config()->set('database.connections.tenant', ['driver' => 'mysql', 'host' => '127.0.0.1', 'database' => 'tenant_a', 'prefix' => '']);
        config()->set('database.connections.elsewhere', ['driver' => 'mysql', 'host' => '127.0.0.1', 'database' => 'tenant_a', 'prefix' => '']);

        $here  = self::user((new IntegrationIdentity)->setConnection('tenant'));
        $there = self::user($elsewhere());

        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        Event::dispatch(new Attempting('web', ['email' => 'ada@example.test', 'password' => self::PASSWORD], false));
        Event::dispatch(new Validated('web', $here));

        self::save($there->forceFill(['password' => Hash::make('another password')]), $runs, 'there, changed');
        self::save($here, $runs, 'here');

        Event::dispatch(new OtherDeviceLogout('admin', $there));

        self::assertSame(['there, changed'], $runs->getArrayCopy());

        Event::dispatch(new OtherDeviceLogout('web', $here));

        self::assertSame(['there, changed', 'here'], $runs->getArrayCopy());
    }

    /**
     * The same key in another tenant's database is another user.
     *
     * @return void
     */
    public function testTheSameKeyInAnotherTenantsDatabaseIsAnotherUser(): void
    {
        config()->set('database.connections.tenant', ['driver' => 'mysql', 'host' => '127.0.0.1', 'database' => 'tenant_a', 'prefix' => '']);

        $here = self::user((new IntegrationIdentity)->setConnection('tenant'));

        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        Event::dispatch(new Attempting('web', ['email' => 'ada@example.test', 'password' => self::PASSWORD], false));
        Event::dispatch(new Validated('web', $here));

        self::save($here, $runs, 'tenant a, held');

        DB::purge('tenant');

        config()->set('database.connections.tenant.database', 'tenant_b');

        $there = self::user((new IntegrationIdentity)->setConnection('tenant'));

        Event::dispatch(new OtherDeviceLogout('web', $there));

        self::save($there, $runs, 'tenant b');

        self::assertSame(['tenant b'], $runs->getArrayCopy());
    }

    /**
     * The validated instance moved to another connection is another user.
     *
     * @return void
     */
    public function testTheValidatedInstanceMovedElsewhereIsAnotherUser(): void
    {
        config()->set('database.connections.tenant', ['driver' => 'mysql', 'host' => '127.0.0.1', 'database' => 'tenant_a', 'prefix' => '']);
        config()->set('database.connections.elsewhere', ['driver' => 'mysql', 'host' => '127.0.0.1', 'database' => 'tenant_b', 'prefix' => '']);

        $user = self::user((new IntegrationIdentity)->setConnection('tenant'));

        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        Event::dispatch(new Attempting('web', ['email' => 'ada@example.test', 'password' => self::PASSWORD], false));
        Event::dispatch(new Validated('web', $user));

        self::save($user->setConnection('elsewhere'), $runs, 'elsewhere');

        self::assertSame(['elsewhere'], $runs->getArrayCopy());
    }

    /**
     * Two model classes over one table are one user for the same row.
     *
     * @return void
     */
    public function testModelClassesOverOneTableAreOneUser(): void
    {
        $staff = self::user(new VerifiableStaffIdentity);

        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        Event::dispatch(new Attempting('admin', ['email' => 'ada@example.test', 'password' => self::PASSWORD], false));
        Event::dispatch(new Validated('admin', $staff));

        self::save($staff, $runs, 'held');

        self::assertSame([], $runs->getArrayCopy());

        Event::dispatch(new OtherDeviceLogout('web', self::user(new VerifiableIdentity)));

        self::save($staff, $runs, 'after the sign-out');

        self::assertSame(['held', 'after the sign-out'], $runs->getArrayCopy());
    }

    /**
     * The model as key 5 with a fresh hash of the password.
     *
     * @template TModel of \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @param  TModel  $model
     * @return TModel
     */
    private static function user(Identity&Model $model): Identity&Model
    {
        return $model->forceFill(['id' => 5, 'password' => Hash::make(self::PASSWORD)]);
    }

    /**
     * Save the user's password over a hash of the same password, recording the
     * change.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $user
     * @param  \ArrayObject<int, string>  $runs
     * @param  string  $name
     * @return void
     */
    private static function save(Identity&Model $user, \ArrayObject $runs, string $name): void
    {
        app(Rehashing::class)->unlessRehash($user, Hash::make(self::PASSWORD), static function () use ($runs, $name): void {
            $runs->append($name);
        });
    }
}
