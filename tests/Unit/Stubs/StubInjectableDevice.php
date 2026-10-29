<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Database\Eloquent\Builder;

/**
 * StubDevice subclass whose `newQuery()` returns an injected Builder mock
 * instead of the default Eloquent builder.
 *
 * Used by `JwtGuardTest::swapDeviceModelToInMemoryInstance()` to wire the
 * guard's `DeviceLookup::find()` path through a pre-built in-memory device
 * whose `authenticatable` relation has been manually set - the refresh-token
 * tests need the relation to survive the round trip without hitting a real
 * polymorphic query.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubInjectableDevice extends StubDevice
{
    /** @var \Illuminate\Database\Eloquent\Builder<\Tests\Unit\Stubs\StubInjectableDevice>|null Builder returned from `newQuery()` when set. */
    public static ?Builder $injectedBuilder = null;

    /**
     * Return the injected Builder mock if present, otherwise fall back to
     * Eloquent's default query builder. A test double overriding the framework
     * query entry point, not model behaviour.
     *
     * @return \Illuminate\Database\Eloquent\Builder<\Tests\Unit\Stubs\StubInjectableDevice>
     *
     * @throws \LogicException
     *
     * @phpstan-ignore sineMaculaLaravel.modelBehaviour
     */
    #[\Override]
    public function newQuery(): Builder
    {
        if (self::$injectedBuilder === null) {
            throw new \LogicException(sprintf('%s::$injectedBuilder must be set before calling newQuery() on this stub.', self::class));
        }

        return self::$injectedBuilder;
    }
}
