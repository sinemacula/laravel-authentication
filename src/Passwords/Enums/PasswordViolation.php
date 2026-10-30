<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords\Enums;

/**
 * A way a new password fails the password policy, so a form can say which rule
 * it broke.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum PasswordViolation: string
{
    // Fewer characters than `min_length`
    case TOO_SHORT = 'too_short';

    // More characters than `max_length`, or more than the 72 bytes bcrypt reads
    // when the hashing driver is bcrypt
    case TOO_LONG = 'too_long';

    // A null character, which bcrypt refuses to hash, when the hashing driver
    // is bcrypt
    case NULL_CHARACTER = 'null_character';

    // No letter, while `letters` is on
    case LETTERS = 'letters';

    // Not both an upper-case and a lower-case letter, while `mixed_case` is on
    case MIXED_CASE = 'mixed_case';

    // No number, while `numbers` is on
    case NUMBERS = 'numbers';

    // No symbol, punctuation or separator, while `symbols` is on
    case SYMBOLS = 'symbols';

    // The breached-password checker found it
    case BREACHED = 'breached';

    // The breached-password checker could not answer, and the policy fails
    // closed (`when_unavailable` is `reject`)
    case BREACH_CHECK_UNAVAILABLE = 'breach_check_unavailable';
}
