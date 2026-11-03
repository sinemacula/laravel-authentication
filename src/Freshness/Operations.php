<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Freshness;

/**
 * The names of the operations this package defines, each configured with a
 * requirement by default. The package asks the freshness policy about
 * `identifier_change` before an identifier change, about
 * `password_establishment` before a password is established for an identity
 * that has none, and, in the factor-change gate the factor package calls before
 * it changes a factor (`SessionService::factorChange()`), about
 * `first_additional_factor` for an identity's first additional factor and
 * `factor_change` for every other change.
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

    /** @var string Adding, replacing or removing a further factor, or generating recovery codes. */
    public const string FACTOR_CHANGE = 'factor_change';

    /** @var string Adding an identity's first additional factor, on an active session, which has no further factor to step up with. */
    public const string FIRST_ADDITIONAL_FACTOR = 'first_additional_factor';

    /**
     * Disallow instantiation; constants only.
     */
    private function __construct() {}
}
