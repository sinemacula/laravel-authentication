<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Facades;

use Illuminate\Support\Facades\Auth as IlluminateAuth;
use SineMacula\Laravel\Authentication\AuthManager;

/**
 * Package `Auth` facade — the supported entry point for the
 * contextual accessors.
 *
 * Subclasses Laravel's framework `Auth` facade so consumers get
 * everything the framework facade gives them (`check`, `user`, `id`,
 * `guard`, `extend`, `provider`, etc.) plus the seven contextual
 * methods exposed directly on the package `AuthManager` subclass:
 * `identity`, `principal`, `device`, `organization`, `scope`,
 * `isInternal`, `isExternal`.
 *
 * Consumers may import either this facade or the framework facade —
 * the underlying `auth` container binding is identical, the package
 * `AuthManager` is bound to it, and the same set of methods resolves
 * either way. The reason to prefer this subclass is that the
 * `@method` annotations below give IDEs (PhpStorm, VS Code, etc.)
 * full autocompletion + return-type inference for every contextual
 * accessor, which the framework facade cannot provide because it has
 * no knowledge of this package.
 *
 * The `getFacadeAccessor()` is inherited unchanged from the parent —
 * the package does NOT introduce a separate container binding; both
 * facades dispatch through the framework's `auth` key, which the
 * package service provider has already replaced with the `AuthManager`
 * subclass at boot time.
 *
 * @see \SineMacula\Laravel\Authentication\AuthManager
 *
 * @method static \SineMacula\Laravel\Authentication\Contracts\Identity|null identity()
 * @method static \SineMacula\Laravel\Authentication\Contracts\Principal|null principal()
 * @method static \SineMacula\Laravel\Authentication\Contracts\Device|null device()
 * @method static \SineMacula\Laravel\Authentication\Contracts\Organization|null organization()
 * @method static string|null scope()
 * @method static bool isInternal()
 * @method static bool isExternal()
 * @method static void inheritDriversFrom(\Illuminate\Auth\AuthManager $existing)
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class Auth extends IlluminateAuth
{
    /**
     * Resolve the package `AuthManager` directly from the container.
     *
     * Convenience helper for consumer code that needs the typed
     * package manager (e.g. for `inheritDriversFrom()` or for code
     * paths where you want a hard reference rather than the facade
     * static dispatch). Equivalent to `app('auth')` but type-narrowed
     * to the package subclass.
     *
     * @return \SineMacula\Laravel\Authentication\AuthManager
     */
    public static function manager(): AuthManager
    {
        $manager = self::getFacadeApplication()?->make('auth');

        assert($manager instanceof AuthManager);

        return $manager;
    }
}
