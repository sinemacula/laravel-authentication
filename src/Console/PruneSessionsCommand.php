<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Console;

use Illuminate\Console\Command;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Events\ModelPruningFinished;
use Illuminate\Database\Events\ModelPruningStarting;
use SineMacula\Laravel\Authentication\SessionRecords\SessionLookup;
use SineMacula\Laravel\Authentication\Sessions\SessionPruning;
use Symfony\Component\Console\Attribute\AsCommand;

/**
 * `authentication:prune-sessions`: deletes the sessions of the configured
 * session model that ended longer ago than
 * `authentication.session.prune_after_days`, with their proofs and provenance
 * (see `SessionPruning`), for a scheduler.
 *
 * It prints what Laravel's `model:prune` prints for a model, and dispatches
 * `ModelPruningStarting` and `ModelPruningFinished` around the run as it does,
 * so a scheduler's logs and listeners read the same. With `--pretend` it counts
 * the sessions it would delete and deletes nothing. A chunk size that is not an
 * integer of 1 or more fails before anything is read; an invalid retention or
 * session model propagates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[AsCommand(name: 'authentication:prune-sessions')]
final class PruneSessionsCommand extends Command
{
    /** @var string The name and signature of the console command. */
    protected $signature = <<<'EOD'
        authentication:prune-sessions
                                    {--chunk=1000 : The number of sessions to delete per chunk}
                                    {--pretend : Display the number of prunable sessions instead of deleting them}
        EOD;

    /** @var string The console command description. */
    protected $description = 'Prune the sessions that ended longer ago than the retention, with their proofs and provenance';

    /**
     * Prune the sessions, or count them with `--pretend`.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SessionPruning  $pruning
     * @param  \Illuminate\Contracts\Events\Dispatcher  $events
     * @return int
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     */
    public function handle(SessionPruning $pruning, Dispatcher $events): int
    {
        $chunk = self::chunkSize($this->option('chunk'));

        if ($chunk === null) {
            $this->components->error('The --chunk option must be an integer of 1 or more.');

            return self::FAILURE;
        }

        $model = SessionLookup::model()::class;

        if ($this->option('pretend') === true) {
            $this->pretendToPrune($pruning, $model);

            return self::SUCCESS;
        }

        $events->dispatch(new ModelPruningStarting([$model]));

        $started = false;

        $total = $pruning->prune($chunk, function (int $total) use ($model, &$started): void {

            if (!$started) {
                $this->newLine();
                $this->components->info("Pruning [{$model}] records.");

                $started = true;
            }

            $this->components->twoColumnDetail($model, "{$total} records");
        });

        if ($total === 0) {
            $this->components->info("No prunable [{$model}] records found.");
        }

        $events->dispatch(new ModelPruningFinished([$model]));

        return self::SUCCESS;
    }

    /**
     * Print how many sessions pruning would delete.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\SessionPruning  $pruning
     * @param  class-string  $model
     * @return void
     *
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     */
    private function pretendToPrune(SessionPruning $pruning, string $model): void
    {
        $count = $pruning->count();

        $this->components->info($count === 0 ? "No prunable [{$model}] records found." : "{$count} [{$model}] records will be pruned.");
    }

    /**
     * The chunk size the option gives: digits naming an integer from 1 up to
     * PHP's largest, or `null` for anything else (a sign, a fraction, text,
     * whitespace, or a number too large).
     *
     * @param  mixed  $option
     * @return ?int
     */
    private static function chunkSize(mixed $option): ?int
    {
        if (!is_string($option) || !ctype_digit($option)) {
            return null;
        }

        $chunk = filter_var($option, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);

        return is_int($chunk) ? $chunk : null;
    }
}
