<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * A password reset link to deliver: what `PasswordResetLinkSender::send()` is
 * given, once the delivery job has checked that the token is still the live one
 * and that the identity may reset its password.
 *
 * The identifier is the destination: the identity's own identifier of the type,
 * in its normal form, exactly the one the link was requested for. The token is
 * in clear, so it is held as a `\SensitiveParameterValue` and read through
 * `token()`: no dump of the message shows it, and serialising the message
 * throws. Never log it or put it anywhere but the link the identity follows.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasswordResetLink
{
    /** @var \SensitiveParameterValue The token, in clear. */
    private \SensitiveParameterValue $token;

    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  string  $type
     * @param  string  $identifier
     * @param  string  $token
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

        // The token, in clear.
        #[\SensitiveParameter]
        string $token,

        /** When the link stops working. */
        public CarbonImmutable $expiresAt,

        /** Recipient of the link. */
        public Identity $identity,
    ) {
        $this->token = new \SensitiveParameterValue($token);
    }

    /**
     * The token, in clear, for the link the identity follows.
     *
     * @return string
     */
    public function token(): string
    {
        return $this->token->getValue();
    }
}
