<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * A password reset link to deliver: what `PasswordResetLinkSender::send()` is
 * given, once the delivery job has checked that the token is still the live one
 * and that the identity may reset its password.
 *
 * The identifier is the destination: the identity's own identifier of the type,
 * in its normal form, exactly the one the link was requested for. The token is
 * a `Secret`, read through `token()`: no dump of the message shows it, and
 * serialising the message throws. Reveal it only into the link the identity
 * follows; never log it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasswordResetLink
{
    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  string  $type
     * @param  string  $identifier
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $token
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     */
    public function __construct(

        /** Guard the link was requested through, whose reset route it is for. */
        public string $guard,

        /** Type of the identifier, for example `email`. */
        public string $type,

        /** Destination: the identity's own identifier of the type, in its normal form. */
        #[\SensitiveParameter] public string $identifier,

        /** The token, read through `token()`. */
        private Secret $token,

        /** When the link stops working. */
        public CarbonImmutable $expiresAt,

        /** Recipient of the link. */
        public Identity $identity,
    ) {}

    /**
     * The token, for the link the identity follows.
     *
     * @return \SineMacula\Laravel\Authentication\Secrets\Secret
     */
    public function token(): Secret
    {
        return $this->token;
    }
}
