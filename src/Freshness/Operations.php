<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Freshness;

/**
 * The names of the operations this package asks the freshness policy about.
 *
 * Any other name an application or another package uses is its own, in the same
 * form: lower-case segments of letters, digits and underscores, each starting
 * with a letter, separated by dots (`mfa.add_factor`, `sso.reauthenticate`).
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

    /** @var string Adding, replacing or removing a further factor. */
    public const string FACTOR_CHANGE = 'factor_change';

    /**
     * Disallow instantiation; constants only.
     */
    private function __construct() {}
}
