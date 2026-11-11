<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Freshness;

/**
 * The names of the operations this package defines, each configured with a
 * requirement by default.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class Operations
{
    /** @var string Changing an identity's email address or phone number. */
    public const string IDENTIFIER_CHANGE = 'identifier_change';

    /** @var string Establishing a password for an identity that has none. */
    public const string PASSWORD_ESTABLISHMENT = 'password_establishment';

    /** @var string Adding, replacing or removing a further factor, or generating recovery codes. */
    public const string FACTOR_CHANGE = 'factor_change';

    /** @var string Adding an identity's first additional factor, on an active session, which has no further factor to step up with. */
    public const string FIRST_ADDITIONAL_FACTOR = 'first_additional_factor';

    /**
     * Disallow instantiation; constants only.
     */
    private function __construct() {}
}
