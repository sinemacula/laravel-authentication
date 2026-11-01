<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * 2D identity on the default connection whose sessions are
 * `SeparateConnectionSession` rows on their own connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SeparateConnectionSessionIdentity extends StubPrincipal
{
    /**
     * The identity's sessions, on the sessions' own connection.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function sessions(): Builder
    {
        return $this->morphMany(SeparateConnectionSession::class, 'authenticatable');
    }
}
