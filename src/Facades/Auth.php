<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Facades;

use Illuminate\Support\Facades\Auth as IlluminateAuth;
use SineMacula\Laravel\Authentication\AuthManager;

/**
 * Laravel's `Auth` facade, typed for the package `AuthManager`'s methods.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @see \SineMacula\Laravel\Authentication\AuthManager
 *
 * @method static \SineMacula\Laravel\Authentication\Contracts\Identity|null identity()
 * @method static \SineMacula\Laravel\Authentication\Contracts\Principal|null principal()
 * @method static \SineMacula\Laravel\Authentication\Contracts\Session|null session()
 * @method static \SineMacula\Laravel\Authentication\Contracts\Tenant|null tenant()
 * @method static list<string>|null scopes()
 * @method static \SineMacula\Laravel\Authentication\Context\AuthenticationContext|null context()
 * @method static \SineMacula\Laravel\Authentication\Jwt\JwtTokenService jwt(?string $guard = null)
 * @method static \SineMacula\Laravel\Authentication\Sessions\SessionService sessions(?string $guard = null)
 * @method static list<string> sessionGuards()
 * @method static \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport refreshTransport(?string $guard = null)
 * @method static \SineMacula\Laravel\Authentication\Codes\CodeService codes(?string $guard = null)
 * @method static \SineMacula\Laravel\Authentication\Passwords\PasswordService passwords(?string $guard = null)
 * @method static \SineMacula\Laravel\Authentication\Passkeys\PasskeyService passkeys(?string $guard = null)
 * @method static \SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService identifierChanges(?string $guard = null)
 * @method static \SineMacula\Laravel\Authentication\ApiKeys\ApiKeyService apiKeys(?string $guard = null)
 * @method static \SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsExchange clientCredentials(?string $guard = null)
 * @method static \SineMacula\Laravel\Authentication\Callers\Caller|null caller()
 * @method static void inheritStateFrom(\Illuminate\Auth\AuthManager $replaced)
 * @method static void forgetGuardState()
 * @method static (\SineMacula\Laravel\Authentication\Contracts\ContextualGuard&\SineMacula\Laravel\Authentication\Contracts\GuardBinding)|null resolvedGuard(string $name)
 */
final class Auth extends IlluminateAuth
{
    /**
     * Resolve the package `AuthManager` from the container.
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
