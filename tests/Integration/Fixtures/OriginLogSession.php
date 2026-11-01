<?php

declare(strict_types = 1);

namespace Tests\Integration\Fixtures;

use SineMacula\Laravel\Authentication\Models\Session;

/**
 * Session model that derives its guard and sign-in method from a
 * `session_origins` row naming it, falling back to its own columns, as an
 * application might record either outside the session row.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class OriginLogSession extends Session
{
    /**
     * Return the guard a `session_origins` row records, falling back to the
     * session's own column.
     *
     * @return ?string
     */
    #[\Override]
    public function getGuard(): ?string
    {
        return $this->origin('guard') ?? parent::getGuard();
    }

    /**
     * Return the sign-in method a `session_origins` row records, falling back
     * to the session's own column.
     *
     * @return ?string
     */
    #[\Override]
    public function getSignInMethod(): ?string
    {
        return $this->origin('sign_in_method') ?? parent::getSignInMethod();
    }

    /**
     * Read a column of the session's `session_origins` row, if it has one.
     *
     * @param  string  $column
     * @return ?string
     */
    private function origin(string $column): ?string
    {
        $value = $this->getConnection()
            ->table('session_origins')
            ->where('session_id', $this->getKey())
            ->value($column);

        return is_string($value) ? $value : null;
    }
}
