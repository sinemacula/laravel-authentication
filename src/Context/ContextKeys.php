<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Context;

/**
 * The rules an authentication context's namespaces and contributed keys keep.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ContextKeys
{
    /** @var string What a namespace looks like. */
    private const string NAMESPACE_PATTERN = '/^[a-z][a-z0-9_]{0,31}$/D';

    /** @var string What a key looks like. */
    private const string KEY_PATTERN = '/^[a-z][a-z0-9_]{0,63}$/D';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether the name is one a contributor's namespace may have.
     *
     * @param  string  $namespace
     * @return bool
     */
    public static function isNamespace(string $namespace): bool
    {
        return $namespace !== AuthenticationContext::NAMESPACE && preg_match(self::NAMESPACE_PATTERN, $namespace) === 1;
    }

    /**
     * The keys contributed under the namespace once checked, or what is wrong
     * with the first that is not.
     *
     * @param  string  $namespace
     * @param  mixed  $keys
     * @return array<string, mixed>|string
     */
    public static function checked(string $namespace, mixed $keys): array|string
    {
        if (!is_array($keys)) {
            return sprintf('The keys contributed under [%s] must be an array.', $namespace);
        }

        $checked = [];

        foreach ($keys as $key => $value) {

            $name    = (string) $key;
            $problem = self::problem($namespace, $name, $value);

            if ($problem !== null) {
                return $problem;
            }

            $checked[$name] = $value;
        }

        return $checked;
    }

    /**
     * What is wrong with one contributed key, or `null` when nothing is.
     *
     * @param  string  $namespace
     * @param  string  $key
     * @param  mixed  $value
     * @return ?string
     */
    private static function problem(string $namespace, string $key, mixed $value): ?string
    {
        if (preg_match(self::KEY_PATTERN, $key) !== 1) {
            return sprintf('The key [%s] contributed under [%s] must be a lower-case letter and then up to 63 lower-case letters, digits or underscores.', $key, $namespace);
        }

        return self::isPlain($value) ? null : sprintf('The value of [%s.%s] must be null, a scalar or an array of them, never an object or a resource.', $namespace, $key);
    }

    /**
     * Whether the value is `null`, a scalar, or an array of those.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function isPlain(mixed $value): bool
    {
        if (!is_array($value)) {
            return $value === null || is_scalar($value);
        }

        foreach ($value as $item) {
            if (!self::isPlain($item)) {
                return false;
            }
        }

        return true;
    }
}
