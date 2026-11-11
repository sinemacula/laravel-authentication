<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Support;

/**
 * Moves closures an object registered on itself onto the object replacing it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ClosureRebinding
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Rebind an anonymous closure from the replaced object to the replacement.
     *
     * @param  object  $replaced
     * @param  object  $replacement
     * @param  \Closure(): mixed  $closure
     * @return \Closure(): mixed
     */
    public static function onto(object $replaced, object $replacement, \Closure $closure): \Closure
    {
        $reflector = new \ReflectionFunction($closure);

        if (!$reflector->isAnonymous() || $reflector->getClosureThis() !== $replaced) {
            return $closure;
        }

        $rebound = $closure->bindTo($replacement);

        assert($rebound instanceof \Closure);

        return $rebound;
    }
}
