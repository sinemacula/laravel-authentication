<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Database\Eloquent\Model;

/**
 * Defers work until the writes made on a model's connection have committed.
 *
 * The package reports what it changed on a device (a revocation, a sign-in)
 * only once the change is durable: at once when the device's connection has no
 * open transaction, otherwise when that transaction commits, and never when it
 * is rolled back. A transaction open on another connection neither delays nor
 * cancels the work, since the device's writes were not made in it.
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
        $manager    = ($this->transactions)();
        $connection = $model->getConnection()->getName();

        $pending = $manager instanceof DatabaseTransactionsManager
            ? $manager->callbackApplicableTransactions()->last(static fn (DatabaseTransactionRecord $transaction): bool => $transaction->connection === $connection)
            : null;

        if ($pending === null) {

            $callback();

            return;
        }

        $pending->addCallback($callback);
    }
}
