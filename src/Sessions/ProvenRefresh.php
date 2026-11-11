<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Jwt\Enums\RotationMatch;

/**
 * The session a refresh token proves, the principal it names and the rotation
 * id it carried.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProvenRefresh
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  mixed  $principalHint
     * @param  \SineMacula\Laravel\Authentication\Jwt\Enums\RotationMatch  $match
     */
    public function __construct(

        /** The session the token proves. */
        public EloquentSession&Model $session,

        /** The principal the token names, its `principal` claim. */
        public mixed $principalHint,

        /** Which of the session's rotation ids the token carried. */
        public RotationMatch $match,
    ) {}
}
