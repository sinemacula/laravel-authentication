<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * Shared tables for test cases that use the `TypedIdentity`, `TypedMembership`
 * and `TypedTenant` fixtures: identities whose memberships may declare a type,
 * acting within tenants that keep theirs in `category`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithTypedPrincipals
{
    /**
     * Create the identity, tenant and membership tables.
     *
     * @return void
     */
    protected static function createTypedPrincipalTables(): void
    {
        Schema::create('typed_identities', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email');
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        Schema::create('typed_tenants', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('category')->nullable();
            $blueprint->timestamps();
        });

        Schema::create('typed_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->unsignedInteger('identity_id');
            $blueprint->unsignedInteger('tenant_id')->nullable();
            $blueprint->string('type')->nullable();
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the tables `createTypedPrincipalTables()` created.
     *
     * @return void
     */
    protected static function dropTypedPrincipalTables(): void
    {
        foreach (['typed_memberships', 'typed_tenants', 'typed_identities'] as $table) {
            Schema::dropIfExists($table);
        }
    }
}
