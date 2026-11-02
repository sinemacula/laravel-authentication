<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;

/**
 * Looks through an exception's trace for a secret the way a reporter that dumps
 * frames would find it: among the arguments of each frame, at any depth of an
 * array, and among the variables a closure argument captured, which
 * `#[\SensitiveParameter]` does not cover; and, with `dumpsInTrace()`, in the
 * whole object graph of every argument as Symfony's VarDumper shows it, private
 * properties and `__debugInfo()` included. Arguments are recorded only while
 * `zend.exception_ignore_args` is off, so `withArgumentsInTraces()` turns it
 * off for the call it runs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InspectsTraces
{
    /**
     * Run the callback with arguments recorded in traces, and return the
     * exception of the class given it threw, failing when it threw none.
     *
     * @template TException of \Throwable
     *
     * @param  class-string<TException>  $exception
     * @param  \Closure(): mixed  $callback
     * @return TException
     */
    protected static function withArgumentsInTraces(string $exception, \Closure $callback): \Throwable
    {
        $ignored = ini_set('zend.exception_ignore_args', '0');

        try {
            $callback();
        } catch (\Throwable $thrown) {
            self::assertInstanceOf($exception, $thrown);
            self::assertNotSame([], array_filter(array_column($thrown->getTrace(), 'args')));

            return $thrown;
        } finally {
            ini_set('zend.exception_ignore_args', (string) $ignored);
        }

        self::fail("No {$exception} was thrown.");
    }

    /**
     * Whether any value matches, at any depth of an array, or among the
     * variables a closure captured.
     *
     * @param  array<array-key, mixed>  $values
     * @param  \Closure(string): bool  $matches
     * @return bool
     */
    protected static function carries(array $values, \Closure $matches): bool
    {
        foreach ($values as $value) {

            $nested = match (true) {
                is_array($value)           => $value,
                $value instanceof \Closure => (new \ReflectionFunction($value))->getStaticVariables(),
                default                    => null,
            };

            if ((is_string($value) && $matches($value)) || ($nested !== null && self::carries($nested, $matches))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Whether any frame of the trace outside the tests themselves, whose
     * closures hand the secret in, carries it, as an argument or a closure's
     * capture.
     *
     * @param  \Throwable  $exception
     * @param  \Closure(string): bool|string  $secret
     * @return bool
     */
    protected static function hasInTrace(\Throwable $exception, #[\SensitiveParameter] \Closure|string $secret): bool
    {
        $frames = array_filter($exception->getTrace(), static fn (array $frame): bool => !str_starts_with($frame['class'] ?? '', 'Tests\\'));

        return self::carries(array_column($frames, 'args'), is_string($secret) ? static fn (string $value): bool => $value === $secret : $secret);
    }

    /**
     * Whether the trace carries the secret as `hasInTrace()` finds it, or the
     * dump of the frames' arguments outside the tests themselves shows it
     * anywhere in their object graphs, the way VarDumper (behind Laravel's
     * `dump` and `dd`) shows them: each object's private properties and its
     * `__debugInfo()`, and each closure's captures and bound object.
     *
     * @param  \Throwable  $exception
     * @param  \Closure(string): bool|string  $secret
     * @return bool
     */
    protected static function dumpsInTrace(\Throwable $exception, #[\SensitiveParameter] \Closure|string $secret): bool
    {
        if (self::hasInTrace($exception, $secret)) {
            return true;
        }

        $frames = array_filter($exception->getTrace(), static fn (array $frame): bool => !str_starts_with($frame['class'] ?? '', 'Tests\\'));
        $cloner = new VarCloner;
        $dumper = new CliDumper;

        $cloner->setMaxItems(20000);
        $dumper->setColors(false);

        $dump = (string) $dumper->dump($cloner->cloneVar(array_column($frames, 'args')), true);

        return is_string($secret) ? str_contains($dump, $secret) : $secret($dump);
    }

    /**
     * A matcher for a signed token anywhere in a value: the three base64url
     * segments of a JWT, whose header and payload both start `eyJ`.
     *
     * @return \Closure(string): bool
     */
    protected static function anyJwt(): \Closure
    {
        return static fn (string $value): bool => preg_match('/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/', $value) === 1;
    }
}
