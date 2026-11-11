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
 * Lets Laravel's `model:prune` delete sessions that ended longer ago than the
 * configured retention, with their proofs and provenance.
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
     * The sessions revoked, or past either deadline, at or before now less the
     * configured retention.
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
     * Prune every prunable session a chunk at a time, dispatching
     * `ModelsPruned` after each chunk as Laravel's own pruning does.
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

        $deleted = $this->newQuery()->whereKey($keys)->forceDelete();

        return is_int($deleted) ? $deleted : 0;
    }
}
