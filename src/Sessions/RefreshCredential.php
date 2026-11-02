<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\EloquentSession;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;

/**
 * Who a refresh credential the request carries would sign in again, without
 * rotating it: the session it proves, its owner, the principal and the active
 * tenant they are admitted as, and where the credential was read from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class RefreshCredential
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Tenant  $tenant
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\EloquentSession  $session
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     */
    public function __construct(

        /** The session's owner, reloaded through the guard's provider. */
        public Identity $identity,

        /** The principal the session acts as. */
        public Principal $principal,

        /** The tenant the session is active in, if any. */
        public ?Tenant $tenant,

        /** The session the credential proves. */
        public EloquentSession&Model $session,

        /** Where the request carried the credential. */
        public RefreshTokenSource $source,
    ) {}
}
