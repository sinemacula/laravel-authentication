<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

/**
 * The `machine_clients` table behind the `MachineClient` fixture, a non-human
 * identity that acts as its own principal, for every test that needs a machine
 * identity beside its own fixtures.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithMachineClients
{
    /**
     * Create the `machine_clients` table.
     *
     * @return void
     */
    protected static function createMachineClientsTable(): void
    {
        Schema::create('machine_clients', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->string('email')->unique();
            $blueprint->string('password')->nullable();
            $blueprint->boolean('is_active')->default(true);
            $blueprint->timestamps();
        });
    }

    /**
     * Drop the `machine_clients` table.
     *
     * @return void
     */
    protected static function dropMachineClientsTable(): void
    {
        Schema::dropIfExists('machine_clients');
    }
}
