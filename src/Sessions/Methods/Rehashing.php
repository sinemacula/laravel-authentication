<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Methods;

/**
 * Marks the automatic rehash of a password on sign-in, so a listener that ends
 * an identity's sessions when its password changes can tell the stored hash
 * being upgraded from the password itself being changed.
 *
 * One instance is shared through the container. The mark lasts only while the
 * callback runs: it is cleared in `finally`, so an exception or a long-running
 * worker never leaves it set for later work.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Rehashing
{
    /** @var int How many rehashes are running, so a nested one does not clear the mark early. */
    private int $depth = 0;

    /**
     * Run the callback marked as an automatic rehash.
     *
     * @template TReturn
     *
     * @param  \Closure(): TReturn  $callback
     * @return TReturn
     *
     * @param-immediately-invoked-callable $callback
     */
    public function during(\Closure $callback): mixed
    {
        $this->depth++;

        try {
            return $callback();
        } finally {
            $this->depth--;
        }
    }

    /**
     * Whether an automatic rehash is running.
     *
     * @return bool
     */
    public function isRunning(): bool
    {
        return $this->depth > 0;
    }
}
