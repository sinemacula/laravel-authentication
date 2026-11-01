<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Authentication\Contracts\ApplicationAccess;
use SineMacula\Laravel\Authentication\Contracts\ApplicationPolicy;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Fixtures\Sessions\GrantedApplicationAccess;
use Tests\Fixtures\Sessions\GrantedApplicationPolicy;

/**
 * Binds an application policy and an application access that decide from rows
 * of their own (`GrantedApplicationPolicy`, `GrantedApplicationAccess`) over a
 * lagging read/write split, so a test can show which copy of those rows they
 * were asked against: a row written through the split connection exists on the
 * primary only, and one withdrawn on the primary is still on the replica.
 *
 * Used beside `InteractsWithLaggingReplica`, whose connections it writes
 * through.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithApplicationGrants
{
    /**
     * Create the grant and verification tables on the primary and the replica,
     * bind the policy over the one bound so far, and bind the access.
     *
     * @return void
     */
    protected function bindGrantedApplicationPolicy(): void
    {
        $this->createOnPrimaryAndReplica(GrantedApplicationAccess::GRANTS, static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('principal_type');
            $blueprint->string('principal_id');
        });

        $this->createOnPrimaryAndReplica(GrantedApplicationPolicy::VERIFICATIONS, static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('identity_id');
            $blueprint->string('type');
        });

        app()->instance(ApplicationPolicy::class, new GrantedApplicationPolicy(app(ApplicationPolicy::class)));
        app()->instance(ApplicationAccess::class, new GrantedApplicationAccess);
    }

    /**
     * Grant the principal the application, on the primary only.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @return int
     */
    protected function grant(Principal $principal): int
    {
        return DB::table(GrantedApplicationAccess::GRANTS)->insertGetId([
            'principal_type' => $principal::class,
            'principal_id'   => IdentifierCoercion::stringify($principal->getPrincipalIdentifier()),
        ]);
    }

    /**
     * Record the identity's identifier of the type verified, on the primary
     * only.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @return int
     */
    protected function verify(Identity $identity, string $type = 'email'): int
    {
        return DB::table(GrantedApplicationPolicy::VERIFICATIONS)->insertGetId([
            'identity_id' => IdentifierCoercion::stringify($identity->getAuthIdentifier()),
            'type'        => $type,
        ]);
    }

    /**
     * Copy the row to the replica, then delete it on the primary, as a replica
     * that lags behind the withdrawal would still hold it.
     *
     * @param  string  $table
     * @param  int  $id
     * @return void
     */
    protected function withdrawOnThePrimary(string $table, int $id): void
    {
        $this->copyRowToReplica($table, $id);

        DB::table($table)->where('id', $id)->delete();

        self::assertFalse(DB::connection(self::PRIMARY_CONNECTION)->table($table)->where('id', $id)->exists());
        self::assertTrue(DB::connection(self::REPLICA_CONNECTION)->table($table)->where('id', $id)->exists());
    }
}
