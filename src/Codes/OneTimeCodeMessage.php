<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Contracts\Identity;

/**
 * A one-time code to deliver: what `OneTimeCodeSender::send()` is given.
 *
 * The identifier is the destination: the recipient's own identifier of the type
 * in its normal form (an E.164 number, a trimmed, lower-cased address), which
 * the delivery job has checked is exactly the one the code is bound to, not a
 * look-alike a database lookup matched. The identity is the recipient the job
 * resolved. The code is in clear, so the message must not be logged.
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
     * @param  string  $code
     * @param  \Carbon\CarbonImmutable  $expiresAt
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     */
    public function __construct(

        /** Guard the code was issued for. */
        public string $guard,

        /** What the code is for: a sign-in, or verifying the identifier. */
        public CodePurpose $purpose,

        /** Type of the identifier, for example `phone` or `email`. */
        public string $type,

        /** Destination: the recipient's own identifier of the type, in its normal form. */
        #[\SensitiveParameter] public string $identifier,

        /** The code, in clear. */
        #[\SensitiveParameter] public string $code,

        /** When the code stops working. */
        public CarbonImmutable $expiresAt,

        /** Recipient of the code. */
        public Identity $identity,
    ) {}
}
