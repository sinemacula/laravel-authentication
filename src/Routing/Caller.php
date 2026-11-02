<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Routing;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Routing\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\Sessions\PendingSession;

/**
 * Who a request is, as the credential its route reads proves it: the guard, the
 * credential, the identity, and the principal, active tenant and session the
 * credential holds, with the pending session a pending credential names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Caller
{
    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Routing\Enums\CallerCredential  $credential
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $session
     * @param  ?\SineMacula\Laravel\Authentication\Sessions\PendingSession  $pending
     */
    public function __construct(

        /** Name of the guard the credential belongs to. */
        public string $guard,

        /** The credential the caller was read from. */
        public CallerCredential $credential,

        /** The identity the credential proves. */
        public Identity $identity,

        /** The principal the credential acts as, or `null` while a pending session waits for the choice. */
        public ?Principal $principal,

        /** The active tenant, or `null` for none. */
        public ?Tenant $tenant,

        /** The session the credential holds, or `null` for a credential without one (an access-only token, an API key). */
        public ?Session $session,

        /** The pending session a pending credential names, or `null` for any other credential. */
        public ?PendingSession $pending = null,
    ) {}
}
