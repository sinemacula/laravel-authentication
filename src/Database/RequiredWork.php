<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

/**
 * The work `AfterCommit` holds for a commit that must run whatever the reports
 * of that commit do (a session's check, a revocation's second pass).
 *
 * Laravel runs a commit's callbacks in turn and stops at the first that throws,
 * so a listener that throws on a report would otherwise skip the work
 * registered after it. Every callback `AfterCommit` registers runs the work
 * held here that is due (its transactions ended, and it has not run) before an
 * exception it throws leaves it, so the report's exception is still thrown,
 * after the work.
 *
 * One instance is shared through the container, scoped, so nothing one request
 * or job holds is run by the next.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RequiredWork
{
    /** @var array<int, array{0: \Closure(): bool, 1: \Closure(): void}> The work held, by number: whether it is due, and the work. */
    private array $held = [];

    /**
     * Hold the work until the closure returned to run it is called, or until it
     * is due and a callback of the commit throws, whichever is first: it runs
     * once. The second closure returned lets it go unrun (its transaction
     * rolled back).
     *
     * @param  \Closure(): bool  $due
     * @param  \Closure(): void  $work
     * @return array{0: \Closure(): void, 1: \Closure(): void}
     */
    public function hold(\Closure $due, \Closure $work): array
    {
        $this->held[] = [$due, $work];

        $number = array_key_last($this->held);

        return [
            function () use ($number): void {
                $this->take($number)?->__invoke();
            },
            function () use ($number): void {
                unset($this->held[$number]);
            },
        ];
    }

    /**
     * Run every work held that is due, each once, in the order it was held. An
     * exception one of them throws does not keep the others from running, and
     * is not thrown: the exception that made the commit stop is.
     *
     * @return void
     */
    public function runDue(): void
    {
        foreach (array_keys($this->held) as $number) {

            $work = $this->takeDue($number);

            if ($work === null) {
                continue;
            }

            try {
                $work();
            } catch (\Throwable) {
                continue;
            }
        }
    }

    /**
     * Let go of the work held under the number and return it when it is due, or
     * `null` when it is not, already ran or was let go.
     *
     * @param  int  $number
     * @return ?\Closure(): void
     */
    private function takeDue(int $number): ?\Closure
    {
        $held = $this->held[$number] ?? null;

        if ($held === null || !$held[0]()) {
            return null;
        }

        return $this->take($number);
    }

    /**
     * Let go of the work held under the number and return it, or `null` when it
     * already ran or was let go.
     *
     * @param  int  $number
     * @return ?\Closure(): void
     */
    private function take(int $number): ?\Closure
    {
        $work = $this->held[$number][1] ?? null;

        unset($this->held[$number]);

        return $work;
    }
}
