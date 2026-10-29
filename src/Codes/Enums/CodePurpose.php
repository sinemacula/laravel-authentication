<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Codes\Enums;

/**
 * What a one-time code was issued for. A code is bound to its purpose, so one
 * issued to verify an identifier never signs anyone in, and one issued to sign
 * in never verifies an identifier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum CodePurpose: string
{
    // A sign-in with a code method (`phone_code`, `email_code`)
    case SIGN_IN = 'sign_in';

    // Verifying an identity's current identifier of a type
    case VERIFY_IDENTIFIER = 'verify_identifier';
}
