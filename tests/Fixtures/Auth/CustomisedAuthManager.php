<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Auth;

use SineMacula\Laravel\Authentication\AuthManager;

/**
 * An application's own auth manager, which extends the package's to add a
 * method of its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CustomisedAuthManager extends AuthManager
{
    /** @var string What `customised()` answers. */
    public const string ANSWER = 'customised';

    /**
     * The application's own method.
     *
     * @return string
     */
    public function customised(): string
    {
        return self::ANSWER;
    }
}
