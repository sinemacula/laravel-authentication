<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Facades;

use Illuminate\Support\Facades\Auth as IlluminateAuth;
use SineMacula\Laravel\Authentication\AuthManager;

/**
 * Package `Auth` facade.
 *
 * Subclasses Laravel's framework `Auth` facade and adds `@method` annotations
 * for every method the package `AuthManager` declares (the contextual accessors
 * and the guards' services), with the types the methods return, so IDEs and
 * static analysis see them. Both this facade and the framework facade resolve
 * through the same `auth` container key, which the package service provider has
 * already replaced with the `AuthManager` subclass.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @see \SineMacula\Laravel\Authentication\AuthManager
 *
 * @method static \SineMacula\Laravel\Authentication\Contracts\Identity|null identity()
 * @method static \SineMacula\Laravel\Authentication\Contracts\Principal|null principal()
 * @method static \SineMacula\Laravel\Authentication\Contracts\Device|null device()
 * @method static \SineMacula\Laravel\Authentication\Contracts\Tenant|null tenant()
 * @method static string|null type()
 * @method static list<string>|null scopes()
 * @method static \SineMacula\Laravel\Authentication\Jwt\JwtTokenService jwt(?string $guard = null)
 * @method static \SineMacula\Laravel\Authentication\Sessions\SessionService sessions(?string $guard = null)
 * @method static \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport refreshTransport(?string $guard = null)
 * @method static \SineMacula\Laravel\Authentication\Codes\CodeService codes(?string $guard = null)
 * @method static \SineMacula\Laravel\Authentication\Passwords\PasswordService passwords(?string $guard = null)
 * @method static \SineMacula\Laravel\Authentication\Passkeys\PasskeyService passkeys(?string $guard = null)
 * @method static \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService identifierChanges(?string $guard = null)
 * @method static \SineMacula\Laravel\Authentication\ApiKeys\ApiKeyService apiKeys(?string $guard = null)
 * @method static \SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsExchange clientCredentials(?string $guard = null)
 * @method static void inheritDriversFrom(\Illuminate\Auth\AuthManager $existing)
 * @method static void forgetGuardState()
 */
final class Auth extends IlluminateAuth
{
    /**
     * Resolve the package `AuthManager` directly from the container. Equivalent
     * to `app('auth')` but type-narrowed to the package subclass.
     *
     * @return \SineMacula\Laravel\Authentication\AuthManager
     *
     * @throws \LogicException
     */
    public static function manager(): AuthManager
    {
        $manager = self::getFacadeApplication()?->make('auth');

        if (!$manager instanceof AuthManager) {

            $message = 'The `auth` container binding did not resolve to an'
                . ' AuthManager instance - check that AuthenticationServiceProvider'
                . ' is registered.';

            throw new \LogicException($message);
        }

        return $manager;
    }
}
