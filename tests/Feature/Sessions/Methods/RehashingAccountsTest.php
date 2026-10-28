<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions\Methods;

use Illuminate\Auth\Events\Attempting;
use Illuminate\Auth\Events\Login;
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
 * Feature tests for how the rehash mark tells Eloquent users apart: by the row
 * they are stored in, as the attempt limit tells accounts apart, so the same
 * key in another database is another user, through Laravel's auth events.
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
     * Rows of `[a user with the same class and key as the attempt's, stored on
     * another connection or in another table]`.
     *
     * @return iterable<string, array{0: \Closure(): (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity)}>
     */
    public static function provideTheSameKeyElsewhere(): iterable
    {
        yield 'on another connection' => [static fn (): IntegrationIdentity => (new IntegrationIdentity)->setConnection('elsewhere')];
        yield 'in another table' => [static fn (): IntegrationIdentity => (new IntegrationIdentity)->setConnection('tenant')->setTable('other_identities')];
    }

    /**
     * Two users of one class and key stored apart are told apart: a change of
     * the one leaves what an attempt for the other takes for its rehash alone,
     * and a forced rehash of the one runs nothing the other's attempt holds.
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
        Event::dispatch(new Login('web', $here, false));
        Event::dispatch(new OtherDeviceLogout('web', $here));

        self::assertSame(['there, changed'], $runs->getArrayCopy());
    }

    /**
     * Once a tenant's connection is switched to another tenant's database, the
     * same key there is another user: a forced rehash of it runs nothing the
     * first tenant's attempt held, and its save runs at once.
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
     * The very instance an attempt validated, moved to another connection, is
     * the user stored there: its save of a fresh hash of the attempt's password
     * is a change, not the attempt's rehash.
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
     * Two model classes over one table are one user for the same row: a forced
     * rehash through the one runs the save held for an attempt that validated
     * the other, and is a change of that user's password, so the attempt takes
     * no save for its rehash from then on.
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
     * change under the name when it runs.
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
