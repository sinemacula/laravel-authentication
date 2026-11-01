<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use Illuminate\Contracts\Database\Eloquent\Builder;

/**
 * Identity capability contract: owns sessions.
 *
 * Implementing identities expose an Eloquent relation builder so bearer-token
 * resolution can look up an Eloquent-backed session record from a hint.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface HasSessions
{
    /**
     * Eloquent relation builder for the identity's sessions.
     *
     * The guard calls it inside `WriteConnection::during()` for the identity,
     * so a query the relation runs while it is built reads the write
     * connection. It must query a model that implements `EloquentSession` (any
     * other is a `LogicException` wherever the package reads it), and the
     * sessions it returns must carry the revocation column: `ActsAsSession`
     * throws for a session loaded without it.
     *
     * @return \Illuminate\Contracts\Database\Eloquent\Builder
     */
    public function sessions(): Builder;
}
