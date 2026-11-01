<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use SineMacula\Laravel\Authentication\Database\SessionRetention;

/**
 * Lets Laravel's `model:prune` delete sessions that are over: revoked, or past
 * its idle or absolute deadline, longer ago than the retention in
 * `authentication.session.prune_after_days`.
 *
 * Retention is counted from the time the session ended (the revocation or the
 * deadline), never from when the session was created, so a session is kept for
 * audit for the same time however long it lasted. A pruned session's tokens
 * fail as an unknown session, just as they already fail once it is revoked or
 * ended, so retention changes nothing about authentication.
 *
 * The trait composes `MassPrunable` and replaces its `prunable()`, so a model
 * opts in with this trait alone: using `MassPrunable` beside it would be a
 * collision of the two `prunable()` methods. Columns come from the
 * `EloquentSession` name accessors.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @phpstan-require-extends \Illuminate\Database\Eloquent\Model
 *
 * @phpstan-require-implements \SineMacula\Laravel\Authentication\Contracts\EloquentSession
 */
trait PrunesSessions
{
    use MassPrunable;

    /**
     * The sessions revoked, or past either deadline, at or before the cutoff:
     * now less the configured retention. Every session time is a whole second,
     * so a deadline is pruned from the second it names.
     *
     * @return \Illuminate\Database\Eloquent\Builder<static>
     *
     * @throws \InvalidArgumentException
     */
    public function prunable(): Builder
    {
        $cutoff = $this->fromDateTime(CarbonImmutable::now()->subDays(SessionRetention::days()));

        return $this->newQuery()->where(function (Builder $query) use ($cutoff): void {
            $query->where($this->getRevokedAtName(), '<=', $cutoff)
                ->orWhere($this->getIdleExpiresAtName(), '<=', $cutoff)
                ->orWhere($this->getAbsoluteExpiresAtName(), '<=', $cutoff);
        });
    }
}
