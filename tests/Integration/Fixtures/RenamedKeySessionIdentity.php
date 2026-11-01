<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use Illuminate\Contracts\Database\Eloquent\Builder;
use Tests\Unit\Stubs\StubPrincipal;

/**
 * 2D identity whose sessions are `RenamedKeySession` rows.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RenamedKeySessionIdentity extends StubPrincipal
{
    /**
     * The identity's sessions, keyed by `session_uuid`.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    #[\Override]
    public function sessions(): Builder
    {
        return $this->morphMany(RenamedKeySession::class, 'authenticatable');
    }
}
