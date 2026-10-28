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
     * Two users of one class and key stored apart are told apart: a save of the
     * one no attempt validated runs at once; each holds its own save; a forced
     * rehash of one runs only its own, and the end of one's attempt drops only
     * its own.
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

        self::save($there, $runs, 'there, unattempted');

        Event::dispatch(new Attempting('admin', ['email' => 'ada@example.test', 'password' => self::PASSWORD], false));
        Event::dispatch(new Validated('admin', $there));

        self::save($here, $runs, 'here');
        self::save($there, $runs, 'there');

        Event::dispatch(new OtherDeviceLogout('web', $here));

        self::save($here, $runs, 'here, dropped');

        Event::dispatch(new Login('web', $here, false));
        Event::dispatch(new OtherDeviceLogout('admin', $there));

        self::assertSame(['there, unattempted', 'here', 'there'], $runs->getArrayCopy());
    }

    /**
     * Once a tenant's connection is switched to another tenant's database, the
     * same key there is another user: its save runs at once rather than being
     * held for the first tenant's attempt, and a forced rehash of it runs
     * nothing the first tenant's attempt held.
     *
     * @return void
     */
    public function testTheSameKeyInAnotherTenantsDatabaseIsAnotherUser(): void
    {
        config()->set('database.connections.tenant', ['driver' => 'mysql', 'host' => '127.0.0.1', 'database' => 'tenant_a', 'prefix' => '']);

        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        Event::dispatch(new Attempting('web', ['email' => 'ada@example.test', 'password' => self::PASSWORD], false));
        Event::dispatch(new Validated('web', self::user((new IntegrationIdentity)->setConnection('tenant'))));

        self::save(self::user((new IntegrationIdentity)->setConnection('tenant')), $runs, 'tenant a, held');

        DB::purge('tenant');

        config()->set('database.connections.tenant.database', 'tenant_b');

        $there = self::user((new IntegrationIdentity)->setConnection('tenant'));

        Event::dispatch(new OtherDeviceLogout('web', $there));

        self::save($there, $runs, 'tenant b');

        self::assertSame(['tenant b'], $runs->getArrayCopy());
    }

    /**
     * Two model classes over one table are one user for the same row, so a save
     * through the one is held for an attempt that validated the other.
     *
     * @return void
     */
    public function testModelClassesOverOneTableAreOneUser(): void
    {
        /** @var \ArrayObject<int, string> $runs */
        $runs = new \ArrayObject;

        Event::dispatch(new Attempting('admin', ['email' => 'ada@example.test', 'password' => self::PASSWORD], false));
        Event::dispatch(new Validated('admin', self::user(new VerifiableStaffIdentity)));

        self::save(self::user(new VerifiableIdentity), $runs, 'held');

        self::assertSame([], $runs->getArrayCopy());

        Event::dispatch(new OtherDeviceLogout('web', self::user(new VerifiableIdentity)));

        self::assertSame(['held'], $runs->getArrayCopy());
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
