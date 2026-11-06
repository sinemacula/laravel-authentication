<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

use Illuminate\Container\Container;
use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Collection;

/**
 * Defers work until the writes made on a model's connection have committed.
 *
 * The package reports what it changed on a session (a revocation, a sign-in)
 * only once the change is durable: at once when the session's connection has no
 * open transaction, otherwise when that transaction commits, and never when it
 * is rolled back. Work that must undo what was done in the meantime can be run
 * on the rollback instead. A transaction open on another connection neither
 * delays nor cancels the work, since the session's writes were not made in it,
 * unless the work names that connection's model as well (`runAcross()`,
 * `runOnceEnded()`).
 *
 * Laravel stops running a commit's callbacks at the first that throws. The work
 * `runAcross()` and `runOnceEnded()` hold is required (a session's check, a
 * revocation's second pass), so a callback registered here that throws first
 * runs the required work that is due (`RequiredWork`), then lets the exception
 * go: a listener that throws on a report cannot skip it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AfterCommit
{
    /**
     * Constructor.
     *
     * @param  \Closure(): mixed  $transactions
     */
    public function __construct(

        /** Returns the current transactions manager, if any, when called. */
        private \Closure $transactions,
    ) {}

    /**
     * Run the callback once the writes made on the model's connection are
     * committed.
     *
     * The manager is resolved when called, as Laravel's event dispatcher does,
     * so a manager swapped in later (by the testing transaction traits, which
     * ignore their own wrapping transaction) is the one consulted.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  \Closure(): void  $callback
     * @return void
     *
     * @imperative
     */
    public function run(Model $model, \Closure $callback): void
    {
        $pending = $this->pending($model);

        if ($pending === null) {

            $callback();

            return;
        }

        $pending->addCallback(self::guarded($callback));
    }

    /**
     * Run the callback once the writes made on each model's connection have
     * committed, the models' connections in the order given: on each, at once
     * when no transaction is open on it then, otherwise when it commits, and
     * never when it rolls back. The work is required: held until it runs or its
     * transaction rolls back (see the class).
     *
     * @param  list<\Illuminate\Database\Eloquent\Model>  $models
     * @param  \Closure(): void  $callback
     * @return void
     *
     * @imperative
     */
    public function runAcross(array $models, \Closure $callback): void
    {
        $model = array_shift($models);

        if ($model === null) {

            $callback();

            return;
        }

        $next    = fn () => $this->runAcross($models, $callback);
        $pending = $this->pending($model);

        if ($pending === null) {

            $next();

            return;
        }

        [$run, $drop] = self::required()->hold(fn (): bool => $this->pending($model) === null, $next);

        $pending->addCallback(self::guarded($run));

        $this->runIfRolledBack($model, $drop);
    }

    /**
     * Run the callback once the transactions open now on each model's
     * connection have ended, the models' connections in the order given: on
     * each, at once when no transaction is open on it then, otherwise when the
     * outermost one open ends, whether it commits or rolls back (one or the
     * other, so it runs once). It is for work that must read past those
     * transactions (not through a snapshot one of them took), not for work that
     * depends on what was written in them. A connection whose level is back to
     * none has no transaction open, though Laravel runs a rollback's callbacks
     * before it forgets the transaction rolled back, so the next model on that
     * connection does not wait for it again. The work is required: held until
     * it runs (see the class).
     *
     * @param  list<\Illuminate\Database\Eloquent\Model>  $models
     * @param  \Closure(): void  $callback
     * @return void
     *
     * @imperative
     */
    public function runOnceEnded(array $models, \Closure $callback): void
    {
        $model = array_shift($models);

        if ($model === null) {

            $callback();

            return;
        }

        $next      = fn () => $this->runOnceEnded($models, $callback);
        $outermost = $this->outermost($model);

        if ($outermost === null) {

            $next();

            return;
        }

        [$run] = self::required()->hold(fn (): bool => $this->outermost($model) === null, $next);

        $outermost->addCallback(self::guarded($run));
        $outermost->addCallbackForRollback(self::guarded($run));
    }

    /**
     * Run the callback, once, if the writes made on the model's connection so
     * far are rolled back: when the innermost transaction open on it now, or
     * any transaction it is nested in, rolls back, whether the inner one had
     * committed into the outer or not. Nothing runs when they commit, nor when
     * no transaction is open, since the writes were then committed as made.
     *
     * The callback is registered with every transaction open on the connection,
     * since not every supported Laravel version runs the rollback callbacks of
     * a nested transaction that had committed into the one rolled back, and
     * runs at most once, whichever of them rolls back first.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @param  \Closure(): void  $callback
     * @return void
     *
     * @imperative
     */
    public function runIfRolledBack(Model $model, \Closure $callback): void
    {
        $ran  = false;
        $once = static function () use (&$ran, $callback): void {

            if ($ran) {
                return;
            }

            $ran = true;

            $callback();
        };

        foreach ($this->open($model) as $transaction) {
            $transaction->addCallbackForRollback(self::guarded($once));
        }
    }

    /**
     * Whether work run now for the model would wait for a commit: whether its
     * connection has a transaction open.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return bool
     */
    public function defers(Model $model): bool
    {
        return $this->pending($model) !== null;
    }

    /**
     * The outermost transaction open on the model's connection that callbacks
     * apply to, or `null` for none or when the connection's level is back to
     * none (a rollback's callbacks run before Laravel forgets the transaction).
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return ?\Illuminate\Database\DatabaseTransactionRecord
     */
    private function outermost(Model $model): ?DatabaseTransactionRecord
    {
        return $model->getConnection()->transactionLevel() === 0 ? null : $this->open($model)->first();
    }

    /**
     * The innermost transaction open on the model's connection that commit
     * callbacks apply to, or `null` for none.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return ?\Illuminate\Database\DatabaseTransactionRecord
     */
    private function pending(Model $model): ?DatabaseTransactionRecord
    {
        return $this->open($model)->last();
    }

    /**
     * The transactions open on the model's connection that callbacks apply to,
     * outermost first; none without a transactions manager.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return \Illuminate\Support\Collection<int, \Illuminate\Database\DatabaseTransactionRecord>
     */
    private function open(Model $model): Collection
    {
        $manager    = ($this->transactions)();
        $connection = $model->getConnection()->getName();

        return $manager instanceof DatabaseTransactionsManager
            ? $manager->callbackApplicableTransactions()->filter(static fn (DatabaseTransactionRecord $transaction): bool => $transaction->connection === $connection)
            : new Collection;
    }

    /**
     * The callback, running the required work that is due before an exception
     * it throws leaves it.
     *
     * @param  \Closure(): void  $callback
     * @return \Closure(): void
     */
    private static function guarded(\Closure $callback): \Closure
    {
        return static function () use ($callback): void {
            try {
                $callback();
            } catch (\Throwable $exception) {
                self::required()->runDue();

                throw $exception;
            }
        };
    }

    /**
     * The required work of the request or job.
     *
     * @return \SineMacula\Laravel\Authentication\Database\RequiredWork
     */
    private static function required(): RequiredWork
    {
        return Container::getInstance()->make(RequiredWork::class);
    }
}
