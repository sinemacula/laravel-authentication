<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Factors;

use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * Everything an additional-factor policy decides on: the guard, who is signing
 * in, how, and from which client.
 *
 * The policy is asked about the identity, after its first factor is verified
 * and before any principal is chosen, so it names no principal or tenant: a
 * tenant that asks more of a session says so through its tenant authentication
 * policy, asked for the destination tenant once a principal is selected.
 *
 * `$provenSession` is set only when the client proved, with its current refresh
 * token, that it holds an existing session of this guard on the same identity,
 * which the sign-in will then replace with a new session: the new session has a
 * new identifier, and nothing a policy kept about the proven one transfers to
 * it. A session merely named by the caller never appears here.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AdditionalFactorContext
{
    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $method
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?string  $clientName
     * @param  ?string  $platform
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $provenSession
     */
    public function __construct(

        /** Guard the sign-in is for. */
        public string $guard,

        /** Identity the primary method verified. */
        public Identity $identity,

        /** Name of the sign-in method that verified the identity. */
        public string $method,

        /** Client the sign-in came from. */
        public ClientContext $client,

        /** Name the client gave itself, if any. */
        public ?string $clientName,

        /** Platform the client reported, if any. */
        public ?string $platform,

        /** Existing session of this guard and identity the client proved it holds, if any. */
        public ?Session $provenSession,
    ) {}
}
