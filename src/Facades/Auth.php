<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Facades;

use Illuminate\Support\Facades\Auth as IlluminateAuth;

/**
 * IDE-friendly subclass of Laravel's Auth facade.
 *
 * Adds `@method` PHPDoc tags for the contextual accessors exposed
 * directly on the package `AuthManager` subclass so IDEs can
 * autocomplete `Auth::principal()`, `Auth::device()`, etc.
 * Consumers may use the framework facade directly — this subclass
 * is purely IDE sugar.
 *
 * @method static \SineMacula\Laravel\Authentication\Contracts\Identity|null identity()
 * @method static \SineMacula\Laravel\Authentication\Contracts\Principal|null principal()
 * @method static \SineMacula\Laravel\Authentication\Contracts\Device|null device()
 * @method static \SineMacula\Laravel\Authentication\Contracts\Organization|null organization()
 * @method static string|null scope()
 * @method static bool isInternal()
 * @method static bool isExternal()
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
final class Auth extends IlluminateAuth {}
