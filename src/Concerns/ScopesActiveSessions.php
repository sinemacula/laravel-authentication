<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use SineMacula\Laravel\Authentication\Sessions\ActiveSessions;

/**
 * The `ActsAsSession` query scope `active()`: sessions that are live, active
 * rather than pending, neither revoked nor past their idle deadline or their
 * absolute deadline when they have one, by the same rule the session list
 * applies, so `Session::query()->active()` and `Auth::sessions()->sessions()`
 * agree.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authentication\Contracts\EloquentSession
 */
trait ScopesActiveSessions
{
    /**
     * Keep the query to sessions that are live now: active, not revoked, and
     * before their idle deadline and their absolute deadline when they have
     * one.
     *
     * @param  \Illuminate\Database\Eloquent\Builder<static>  $query
     * @return void
     */
    protected function scopeActive(Builder $query): void
    {
        ActiveSessions::constrain($query, $this, CarbonImmutable::now());
    }
}
