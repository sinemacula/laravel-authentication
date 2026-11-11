<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;

/**
 * What a sign-in left pending writes its session with.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PendingSessionDraft
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  non-empty-list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement>  $requires
     * @param  ?string  $identifierType
     * @param  \SineMacula\Laravel\Authentication\Proofs\SignInProof  $proof
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $proven
     * @param  ?list<array<string, string>>  $attemptWindows
     */
    public function __construct(

        /** The identity that signed in. */
        public Identity $identity,

        /** The principal selected, or `null` while a choice is outstanding. */
        public ?Principal $principal,

        /** The tenant the principal is to be active in, if any. */
        public ?Tenant $tenant,

        /** What the session waits on, in order. */
        public array $requires,

        /** The type of identifier the sign-in used, if any. */
        public ?string $identifierType,

        /** What the sign-in proved, recorded as the session's first proof. */
        public SignInProof $proof,

        /** The session the client proved it holds, if any. */
        public ?Session $proven = null,

        /** The windows of the attempt-limit slots the sign-in holds. */
        public ?array $attemptWindows = null,
    ) {}
}
