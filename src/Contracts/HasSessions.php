<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Contracts\Database\Eloquent\Builder;

/**
 * An identity that owns sessions.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface HasSessions
{
    /**
     * Eloquent relation builder for the identity's sessions, over a model that
     * implements `EloquentSession`.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    public function sessions(): Builder;
}
