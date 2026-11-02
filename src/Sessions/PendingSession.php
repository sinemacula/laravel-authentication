<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;

/**
 * A session waiting on requirements: a further factor, a choice of principal,
 * or both, in that order. It holds no access or refresh token; its pending
 * credential, handed out once in a result's body, is what every action on it
 * presents.
 *
 * The id is the session's key: it stays the same from pending to active and
 * grants nothing by itself. Only the actions of the first outstanding
 * requirement are allowed (`allows()`); the eligible principals are listed only
 * while the choice is that requirement.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PendingSession
{
    /**
     * Constructor.
     *
     * @param  mixed  $id
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  non-empty-list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement>  $requires
     * @param  string  $method
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  \SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  list<\SineMacula\Laravel\Authentication\Contracts\Principal>  $principals
     */
    public function __construct(

        /** The session's key: its public id, the same once it activates, granting nothing. */
        public mixed $id,

        /** Name of the guard (the application) the session belongs to. */
        public string $guard,

        /** Identity the session's first factor proved. */
        public Identity $identity,

        /** Principal the session is to act as, or `null` while the choice is outstanding. */
        public ?Principal $principal,

        /** Tenant the session is to be active in, or `null` for none or while the choice is outstanding. */
        public ?Tenant $tenant,

        /** What the session waits on, in the order it must be met. */
        public array $requires,

        /** Name of the sign-in method that verified the first factor. */
        public string $method,

        /** When the pending credential, and the session with it, ends unless it activates. */
        public CarbonImmutable $expiresAt,

        /** The session record. */
        public Session $session,

        /** The principals the identity may choose from, listed only while the choice is the first requirement. */
        public array $principals = [],
    ) {}

    /**
     * Whether the pending credential may be used for the action now: whether it
     * is one of the first outstanding requirement's.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction  $action
     * @return bool
     */
    public function allows(PendingAction $action): bool
    {
        return in_array($action, $this->actions(), true);
    }

    /**
     * The actions the pending credential may be used for now: the first
     * outstanding requirement's.
     *
     * @return list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction>
     */
    public function actions(): array
    {
        return $this->requires[0]->actions();
    }
}
