<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Authentication\Models\Session;

/**
 * Shipped session model whose global scope selects its key and status only.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class KeySelectingSession extends Session
{
    /**
     * Add the selecting scope.
     *
     * @return void
     */
    #[\Override]
    protected static function booted(): void
    {
        parent::booted();

        self::addGlobalScope('selecting', static fn (Builder $query): Builder => $query->select(['id', 'status']));
    }
}
