<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Database;

/**
 * The work `AfterCommit` holds for a commit that must run whatever the reports
 * of that commit do.
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
     * Hold the work, returning a closure that runs it once.
     *
     * @param  \Closure(): bool  $due
     * @param  \Closure(): void  $work
     * @return \Closure(): void
     */
    public function hold(\Closure $due, \Closure $work): \Closure
    {
        $this->held[] = [$due, $work];

        $number = array_key_last($this->held);

        return function () use ($number): void {
            $this->take($number)?->__invoke();
        };
    }

    /**
     * Run every work held that is due, each once, in the order it was held,
     * swallowing their exceptions.
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
     * `null` when it is not or already ran.
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
     * already ran.
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
