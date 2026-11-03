<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Support;

/**
 * Moves the closures one object registered on itself onto the object that
 * replaces it, as the package's auth manager does with what was registered on
 * the framework manager it replaces.
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
     * The closure, bound to the replacement when it is an anonymous one bound
     * to the replaced object; any other is returned as it is (a first-class
     * callable keeps the object whose method it is).
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
