<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Concerns;

use Carbon\CarbonImmutable;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Events\ModelsPruned;
use SineMacula\Laravel\Authentication\Database\SessionRetention;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Models\SessionProvenance;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Lets Laravel's `model:prune` delete sessions that are over: revoked, or past
 * their idle or absolute deadline, longer ago than the retention in
 * `authentication.session.prune_after_days`, with their proofs and provenance.
 *
 * Retention is counted from the time the session ended (the revocation or the
 * deadline), never from when the session was created, so a session is kept for
 * audit for the same time however long it lasted. A session with no absolute
 * deadline is pruned once it goes idle or is revoked: a `null` absolute
 * deadline never matches the absolute condition. A pruned session's tokens fail
 * as an unknown session, just as they already fail once it is revoked or ended,
 * so retention changes nothing about authentication.
 *
 * The trait composes `MassPrunable` and replaces its `prunable()` and
 * `pruneAll()`, so a model opts in with this trait alone: using `MassPrunable`
 * beside it would be a collision of the two `prunable()` methods. Columns come
 * from the `EloquentSession` name accessors.
 *
 * Sessions are pruned in chunks, each in one transaction on the session's
 * connection: the keys of up to a chunk of prunable sessions are read, the
 * proofs and provenance recorded for those keys are deleted (by the keys as
 * strings, bound to the string column they are recorded in, whatever the
 * session model's key type), then the sessions themselves. A session deleted
 * any other way leaves its proofs and provenance behind.
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

    /**
     * Prune every prunable session, a chunk at a time, with its proofs and
     * provenance, dispatching `ModelsPruned` after each chunk with the running
     * total, as Laravel's own pruning does.
     *
     * @param  int  $chunkSize
     * @return int
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     */
    public function pruneAll(int $chunkSize = 1000): int
    {
        $total = 0;

        while (($count = $this->getConnection()->transaction(fn (): int => $this->pruneChunk($chunkSize))) > 0) {

            $total += $count;

            event(new ModelsPruned(static::class, $total));
        }

        return $total;
    }

    /**
     * Delete one chunk of prunable sessions with their proofs and provenance,
     * in the caller's transaction, and answer how many sessions it deleted.
     *
     * @param  int  $chunkSize
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    private function pruneChunk(int $chunkSize): int
    {
        $query = $this->prunable();

        if ($query->getQuery()->limit === null) {
            $query->limit($chunkSize);
        }

        $keys = $query->pluck($this->getKeyName())->all();

        if ($keys === []) {
            return 0;
        }

        $recorded = array_values(array_filter(array_map(IdentifierCoercion::stringify(...), $keys), is_string(...)));

        (new SessionProof)->newQuery()->whereIn('session_id', $recorded)->delete();
        (new SessionProvenance)->newQuery()->whereIn('session_id', $recorded)->delete();

        $deleted = $this->newQuery()->whereKey($keys)->delete();

        return is_int($deleted) ? $deleted : 0;
    }
}
