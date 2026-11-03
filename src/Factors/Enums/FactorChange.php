<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Factors\Enums;

use SineMacula\Laravel\Authentication\Freshness\Operations;

/**
 * A change the factor package makes to an identity's further factors, which it
 * asks the factor-change gate about first (`SessionService::factorChange()`).
 * The values are the factor package's operations of the same meaning;
 * `ADD_FIRST` is its `mfa.add_factor` made by an identity with no further
 * factor yet, named apart in the same namespace because it is held to
 * `first_additional_factor`, not `factor_change`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum FactorChange: string
{
    // Adding a further factor to an identity that already has one
    case ADD = 'mfa.add_factor';

    // Adding an identity's first additional factor, on an active session: it
    // has no further factor to step up with
    case ADD_FIRST = 'mfa.add_first_additional_factor';

    // Replacing one of the identity's further factors with another
    case REPLACE = 'mfa.replace_factor';

    // Removing one of the identity's further factors
    case REMOVE = 'mfa.remove_factor';

    // Generating the identity's recovery codes
    case GENERATE_RECOVERY_CODES = 'mfa.generate_recovery_codes';

    /**
     * The freshness operation the change must be fresh for:
     * `first_additional_factor` for an identity's first additional factor,
     * `factor_change` for every other.
     *
     * @return string
     */
    public function operation(): string
    {
        return $this === self::ADD_FIRST ? Operations::FIRST_ADDITIONAL_FACTOR : Operations::FACTOR_CHANGE;
    }

    /**
     * Whether the change names the factor it acts on, whose own proofs never
     * authorise it: a replacement or a removal.
     *
     * @return bool
     */
    public function namesFactor(): bool
    {
        return $this === self::REPLACE || $this === self::REMOVE;
    }
}
