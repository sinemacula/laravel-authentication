<?php

declare(strict_types = 1);

namespace Tests\Unit\Stubs;

use Illuminate\Database\Eloquent\Builder;

/**
 * StubSession whose `newQuery()` returns an injected builder.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubInjectableSession extends StubSession
{
    /** @var \Illuminate\Database\Eloquent\Builder<\Tests\Unit\Stubs\StubInjectableSession>|null Builder returned from `newQuery()` when set. */
    public static ?Builder $injectedBuilder = null;

    /**
     * Return the injected builder if set, otherwise Eloquent's default one.
     *
     * @return \Illuminate\Database\Eloquent\Builder<\Tests\Unit\Stubs\StubInjectableSession>
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
