<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Events\ModelsPruned;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Database\SessionRetention;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Models\SessionProof;
use SineMacula\Laravel\Authentication\Models\SessionProvenance;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Deletes the sessions of the configured session model that are over: revoked,
 * or past their idle or absolute deadline, longer ago than the retention in
 * `authentication.session.prune_after_days`, with their proofs and provenance.
 * `authentication:prune-sessions` runs it; an application can call it itself.
 *
 * Retention is counted from the time the session ended (the revocation or the
 * deadline), never from when the session was created, so a session is kept for
 * audit for the same time however long it lasted. A session with no absolute
 * deadline is pruned once it goes idle or is revoked: a `null` absolute
 * deadline never matches the absolute condition. Every session time is a whole
 * second, so a deadline is pruned from the second it names. A pruned session's
 * tokens fail as an unknown session, just as they already fail once it is
 * revoked or ended, so retention changes nothing about authentication. Columns
 * come from the `EloquentSession` name accessors, and the model's global scopes
 * still narrow what is pruned: the three conditions are grouped inside them.
 *
 * Sessions are pruned in chunks, each in one transaction on the session model's
 * connection (a savepoint inside a caller's): the keys of up to a chunk of
 * prunable sessions are read with a locking read in key order, the order bulk
 * revocations lock sessions in, so each session is judged on its current row
 * rather than an older snapshot, and a refresh that extends a session's idle
 * deadline either commits first (the row no longer matches) or waits until the
 * chunk commits; on PostgreSQL at REPEATABLE READ a row changed after the
 * caller's snapshot fails to serialise instead, deleting nothing. The proofs
 * and provenance recorded for those keys are deleted next (by the keys as
 * strings, bound to the string column they are recorded in, whatever the
 * session model's key type), then the sessions themselves, deleted outright
 * even on a model that soft-deletes (a soft-deleted session would never be
 * selected again, and its IP address and user agent would be kept for good). A
 * session a soft-deleting model has already soft-deleted is outside its scope,
 * so it is never selected. A session deleted any other way leaves its proofs
 * and provenance behind, so whatever deletes sessions otherwise (a truncation
 * included) should delete the rows recorded under their keys too; a sign-in
 * whose new session reuses such a key deletes them before recording its own, so
 * they never count for it.
 *
 * After each chunk's transaction returns, `ModelsPruned` reports the sessions
 * pruned so far, as Laravel's own pruning does: committed when the call runs
 * outside a transaction, provisional inside a caller's (whose rollback brings
 * every chunk back). A listener or progress callback that throws stops the run,
 * and the chunks already committed stay deleted.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SessionPruning
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     */
    public function __construct(

        /** Reports each chunk pruned. */
        private Dispatcher $events,
    ) {}

    /**
     * How many sessions pruning would delete now, read on the write connection
     * by the same conditions `prune()` selects by.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    public function count(): int
    {
        $model  = SessionLookup::model();
        $cutoff = self::cutoff($model);

        return WriteConnection::query(self::prunable($model, $cutoff))->count();
    }

    /**
     * Delete every prunable session, a chunk at a time, with its proofs and
     * provenance, and return how many sessions were deleted. The cutoff is read
     * once, before the first read, and every chunk is judged against it. After
     * each chunk `ModelsPruned` reports the running total, and the callback,
     * when given, receives it.
     *
     * @param  int  $chunkSize
     * @param  ?\Closure(int): void  $pruned
     * @return int
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function prune(int $chunkSize = 1000, ?\Closure $pruned = null): int
    {
        self::assertChunkSize($chunkSize);

        $model  = SessionLookup::model();
        $cutoff = self::cutoff($model);
        $total  = 0;

        while (($count = $model->getConnection()->transaction(static fn (): int => self::pruneChunk($model, $cutoff, $chunkSize))) > 0) {

            $total += $count;

            $this->events->dispatch(new ModelsPruned($model::class, $total));

            if ($pruned === null) {
                continue;
            }

            $pruned($total);
        }

        return $total;
    }

    /**
     * Refuse a chunk size below 1, which would prune nothing for ever.
     *
     * @param  int  $chunkSize
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private static function assertChunkSize(int $chunkSize): void
    {
        if ($chunkSize < 1) {
            throw new \InvalidArgumentException('The chunk size must be at least 1.');
        }
    }

    /**
     * Now less the configured retention, as the session model stores a time.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $model
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function cutoff(EloquentSession&Model $model): string
    {
        return (string) $model->fromDateTime(CarbonImmutable::now()->subDays(SessionRetention::days()));
    }

    /**
     * The sessions revoked, or past either deadline, at or before the cutoff,
     * within the model's global scopes.
     *
     * @formatter:off
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $model
     * @param  string  $cutoff
     * @return \Illuminate\Database\Eloquent\Builder<\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession>
     *
     * @formatter:on
     */
    private static function prunable(EloquentSession&Model $model, string $cutoff): Builder
    {
        return $model->newQuery()->where(static function (Builder $query) use ($model, $cutoff): void {
            $query->where($model->getRevokedAtName(), '<=', $cutoff)
                ->orWhere($model->getIdleExpiresAtName(), '<=', $cutoff)
                ->orWhere($model->getAbsoluteExpiresAtName(), '<=', $cutoff);
        });
    }

    /**
     * Delete one chunk of prunable sessions with their proofs and provenance,
     * in the caller's transaction, and answer how many sessions it deleted.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $model
     * @param  string  $cutoff
     * @param  int  $chunkSize
     * @return int
     */
    private static function pruneChunk(EloquentSession&Model $model, string $cutoff, int $chunkSize): int
    {
        $keys = WriteConnection::query(self::prunable($model, $cutoff))
            ->orderBy($model->getQualifiedKeyName())
            ->limit($chunkSize)
            ->lockForUpdate()
            ->pluck($model->getKeyName())
            ->all();

        if ($keys === []) {
            return 0;
        }

        $recorded = array_values(array_filter(array_map(IdentifierCoercion::stringify(...), $keys), is_string(...)));

        (new SessionProof)->newQuery()->whereIn('session_id', $recorded)->delete();
        (new SessionProvenance)->newQuery()->whereIn('session_id', $recorded)->delete();

        $deleted = $model->newQuery()->whereKey($keys)->forceDelete();

        return is_int($deleted) ? $deleted : 0;
    }
}
