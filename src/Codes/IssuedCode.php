<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes;

use Carbon\CarbonImmutable;

/**
 * A one-time code just issued: the code in clear, which exists only here and in
 * the encrypted delivery job, the issuance it belongs to, and when it expires.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class IssuedCode
{
    /**
     * Constructor.
     *
     * @param  string  $code
     * @param  string  $issueId
     * @param  \Carbon\CarbonImmutable  $expiresAt
     */
    public function __construct(

        /** The code, in clear. */
        #[\SensitiveParameter] public string $code,

        /** Random identifier of this issuance, which a later issuance for the binding replaces. */
        public string $issueId,

        /** When the code stops working. */
        public CarbonImmutable $expiresAt,
    ) {}
}
