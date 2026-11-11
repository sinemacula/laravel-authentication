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
     * Run the required callback once the writes made on each model's connection
     * have committed, in the order given.
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
     * Run the required callback once the transactions open now on each model's
     * connection have committed or rolled back, in the order given.
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
     * Run the callback once if the writes on the model's connection roll back.
     * Some Laravel versions skip a committed nested transaction's rollback
     * callbacks, so it is registered on every open one.
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
     * Whether the model's connection has a transaction open.
     *
     * @param  \Illuminate\Database\Eloquent\Model  $model
     * @return bool
     */
    public function defers(Model $model): bool
    {
        return $this->pending($model) !== null;
    }

    /**
     * The outermost transaction open on the model's connection, or `null` once
     * its level is back to none, since Laravel runs a rollback's callbacks
     * before it forgets the transaction.
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
     * The transactions open on the model's connection, outermost first.
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
     * Wrap the callback to run the due required work before an exception leaves
     * it, since Laravel stops a commit's callbacks at the first that throws.
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
