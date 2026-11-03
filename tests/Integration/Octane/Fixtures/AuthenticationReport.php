<?php

declare(strict_types = 1);

namespace Tests\Integration\Octane\Fixtures;

use SineMacula\Laravel\Authentication\Callers\Caller;
use SineMacula\Laravel\Authentication\Contracts\ContextualGuard;
use SineMacula\Laravel\Authentication\Facades\Auth;

/**
 * Everything the package says about who is authenticated, as the application
 * serving the request (or running the job) sees it now: the default guard, what
 * each guard named has bound (identity, principal, session and tenant
 * identifiers, and scopes), the caller of the request, and its authentication
 * context as plain values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class AuthenticationReport
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The report, each guard resolved in the order given.
     *
     * @param  list<string>  $guards
     * @return array{default: string, guards: array<string, array<string, mixed>>, caller: ?array<string, mixed>, context: ?array<string, mixed>}
     *
     * @throws \Throwable
     */
    public static function of(array $guards): array
    {
        $bound = [];

        foreach ($guards as $name) {
            $bound[$name] = self::guard($name);
        }

        return [
            'default' => Auth::getDefaultDriver(),
            'guards'  => $bound,
            'caller'  => self::caller(Auth::caller()),
            'context' => Auth::context()?->toArray(),
        ];
    }

    /**
     * What a guard reports for a guest.
     *
     * @return array{identity: null, principal: null, session: null, tenant: null, scopes: null}
     */
    public static function guest(): array
    {
        return ['identity' => null, 'principal' => null, 'session' => null, 'tenant' => null, 'scopes' => null];
    }

    /**
     * What the named guard has bound.
     *
     * @param  string  $name
     * @return array{identity: mixed, principal: mixed, session: mixed, tenant: mixed, scopes: ?list<string>}
     */
    private static function guard(string $name): array
    {
        $guard = Auth::manager()->guard($name);

        assert($guard instanceof ContextualGuard);

        return [
            'identity'  => $guard->identity()?->getAuthIdentifier(),
            'principal' => $guard->principal()?->getPrincipalIdentifier(),
            'session'   => $guard->session()?->getSessionIdentifier(),
            'tenant'    => $guard->tenant()?->getTenantIdentifier(),
            'scopes'    => $guard->scopes(),
        ];
    }

    /**
     * The caller as plain values, or `null` for none.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Callers\Caller  $caller
     * @return ?array<string, mixed>
     */
    private static function caller(?Caller $caller): ?array
    {
        if ($caller === null) {
            return null;
        }

        return [
            'guard'      => $caller->guard,
            'credential' => $caller->credential->value,
            'identity'   => $caller->identity->getAuthIdentifier(),
            'principal'  => $caller->principal?->getPrincipalIdentifier(),
            'tenant'     => $caller->tenant?->getTenantIdentifier(),
            'session'    => $caller->session?->getSessionIdentifier(),
            'pending'    => $caller->pending?->id,
        ];
    }
}
