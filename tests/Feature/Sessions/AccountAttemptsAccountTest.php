<?php

declare(strict_types = 1);

namespace Tests\Feature\Sessions;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Sessions\AccountAttempts;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\VerifiableIdentity;
use Tests\Integration\Fixtures\VerifiableStaffIdentity;
use Tests\TestCase;

/**
 * Feature tests for what identifies an Eloquent identity's account to its
 * attempt limit: the row it is stored in, whichever model class reads it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AccountAttempts::class)]
final class AccountAttemptsAccountTest extends TestCase
{
    /**
     * A model's account is its connection, that connection's database, its
     * table with the connection's prefix, and its key.
     *
     * @return void
     */
    public function testAModelsAccountIsTheRowItIsStoredIn(): void
    {
        $connection = DB::connection();
        $identity   = (new IntegrationIdentity)->forceFill(['id' => 42]);

        $expected = implode("\0", ['row', $connection->getName(), $connection->getDatabaseName(), $connection->getTablePrefix() . 'integration_identities', '42']);

        self::assertSame($expected, AccountAttempts::account($identity));
    }

    /**
     * Two model classes over one table (an admin model over the users table,
     * say) name the same account for the same row, and different rows name
     * different accounts.
     *
     * @return void
     */
    public function testModelClassesOverOneTableNameOneAccount(): void
    {
        $identity = (new VerifiableIdentity)->forceFill(['id' => 7]);
        $staff    = (new VerifiableStaffIdentity)->forceFill(['id' => 7]);
        $other    = (new VerifiableStaffIdentity)->forceFill(['id' => 8]);

        self::assertSame(AccountAttempts::account($identity), AccountAttempts::account($staff));
        self::assertNotSame(AccountAttempts::account($staff), AccountAttempts::account($other));
    }

    /**
     * The same key in another database, another table, under another table
     * prefix or on another connection is another account, so one tenant's
     * failures never use up another tenant's limit when the counters live on a
     * central connection.
     *
     * @return void
     */
    public function testTheSameKeyElsewhereIsAnotherAccount(): void
    {
        config()->set('database.connections.tenant', ['driver' => 'mysql', 'host' => '127.0.0.1', 'database' => 'tenant_a', 'prefix' => '']);

        $tenantA = AccountAttempts::account((new IntegrationIdentity)->setConnection('tenant')->forceFill(['id' => 5]));

        DB::purge('tenant');

        config()->set('database.connections.tenant.database', 'tenant_b');

        $tenantB = AccountAttempts::account((new IntegrationIdentity)->setConnection('tenant')->forceFill(['id' => 5]));

        DB::purge('tenant');

        config()->set('database.connections.tenant.prefix', 'b_');

        $prefixed = AccountAttempts::account((new IntegrationIdentity)->setConnection('tenant')->forceFill(['id' => 5]));

        config()->set('database.connections.elsewhere', ['driver' => 'mysql', 'host' => '127.0.0.1', 'database' => 'tenant_a', 'prefix' => '']);

        $elsewhere = AccountAttempts::account((new IntegrationIdentity)->setConnection('elsewhere')->forceFill(['id' => 5]));
        $table     = AccountAttempts::account((new VerifiableIdentity)->setConnection('tenant')->forceFill(['id' => 5]));

        self::assertCount(5, array_unique([$tenantA, $tenantB, $prefixed, $elsewhere, $table]));
    }

    /**
     * The table is the one the database holds, the connection's prefix joined
     * to the model's table name, so a table reached once through a prefix and
     * once through a full table name is one account.
     *
     * @return void
     */
    public function testATablePrefixAndTableNameNameTheTableTheyJoinTo(): void
    {
        config()->set('database.connections.tenant', ['driver' => 'mysql', 'host' => '127.0.0.1', 'database' => 'tenant_a', 'prefix' => '']);

        $unprefixed = AccountAttempts::account((new IntegrationIdentity)->setConnection('tenant')->forceFill(['id' => 5]));

        DB::purge('tenant');

        config()->set('database.connections.tenant.prefix', 'integration_');

        $prefixed = AccountAttempts::account((new IntegrationIdentity)->setTable('identities')->setConnection('tenant')->forceFill(['id' => 5]));

        self::assertSame($unprefixed, $prefixed);
    }
}
