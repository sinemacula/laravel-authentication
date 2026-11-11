<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;

/**
 * Which guard kind a bearer credential belongs to, on a route that lists both.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BearerForms
{
    /** @var string The request attribute the `auth` middleware records the route's guard names under, `null` for the default guard. */
    public const string ROUTE_GUARDS = 'authentication.route_guards';

    /** @var string The driver of the guards that own a credential in JWT form. */
    public const string JWT = 'jwt';

    /** @var string The driver of the guards that own a credential in API key form. */
    public const string API_KEY = 'api_key';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Whether the credential is in JWT form: it contains a `.`.
     *
     * @param  string  $credential
     * @return bool
     */
    public static function isJwtForm(#[\SensitiveParameter] string $credential): bool
    {
        return str_contains($credential, '.');
    }

    /**
     * Whether a guard of the driver leaves the credential to another guard the
     * request's route lists.
     *
     * @param  string  $driver
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $credential
     * @return bool
     */
    public static function defersTo(string $driver, Request $request, #[\SensitiveParameter] string $credential): bool
    {
        $owner = self::isJwtForm($credential) ? self::JWT : self::API_KEY;

        return $owner !== $driver && self::listsGuardOf($owner, $request);
    }

    /**
     * Whether a guard the `auth` middleware recorded for the request's route is
     * configured with the driver, a `null` name being the default guard.
     *
     * @param  string  $driver
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    private static function listsGuardOf(string $driver, Request $request): bool
    {
        $listed = $request->attributes->get(self::ROUTE_GUARDS);

        if (!is_array($listed)) {
            return false;
        }

        $config     = Container::getInstance()->make(Repository::class);
        $configured = $config->get('auth.guards');
        $default    = $config->get('auth.defaults.guard');

        foreach ($listed as $name) {

            $name ??= $default;
            $guard = is_string($name) && is_array($configured) ? ($configured[$name] ?? null) : null;

            if (is_array($guard) && ($guard['driver'] ?? null) === $driver) {
                return true;
            }
        }

        return false;
    }
}
