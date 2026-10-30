<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Auth;

use Illuminate\Auth\AuthManager;

/**
 * Another package's subclass of Laravel's auth manager, which overrides the
 * default guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class LaravelAuthManagerSubclass extends AuthManager
{
    /** @var string The guard this manager's own default guard would be. */
    public const string DEFAULT_GUARD = 'subclass_default';

    /**
     * The manager's own default guard.
     *
     * @return string
     */
    #[\Override]
    public function getDefaultDriver(): string
    {
        return self::DEFAULT_GUARD;
    }
}
