<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * A one-time code to deliver: what `OneTimeCodeSender::send()` is given.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class OneTimeCodeMessage
{
    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $purpose
     * @param  string  $type
     * @param  string  $identifier
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $code
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     */
    public function __construct(

        /** Guard the code was issued for. */
        public string $guard,

        /** What the code is for: a sign-in, verifying the identifier, a further factor, a factor's enrolment, a password reset, or proving a new identifier. */
        public CodePurpose $purpose,

        /** Type of the identifier, for example `phone` or `email`. */
        public string $type,

        /** Destination, in its normal form: the recipient's own identifier of the type, or the new one a change would set. */
        #[\SensitiveParameter] public string $identifier,

        /** The code. */
        public Secret $code,

        /** When the code stops working. */
        public CarbonImmutable $expiresAt,

        /** Recipient of the code. */
        public Identity $identity,
    ) {}
}
