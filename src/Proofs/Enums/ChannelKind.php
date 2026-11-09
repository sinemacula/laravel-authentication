<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs\Enums;

/**
 * The kind of channel a proof was made over: a password, a code sent by text
 * message or email, an authenticator app, a passkey, an external provider, the
 * application's own account recovery, or one the method did not name.
 *
 * The values are the further-factor package's own.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ChannelKind: string
{
    // A password the identity knows
    case PASSWORD = 'password';

    // A code sent by text message to a phone number
    case SMS = 'sms';

    // A code sent to an email address
    case EMAIL = 'email';

    // A code an authenticator app generated
    case AUTHENTICATOR_APP = 'authenticator_app';

    // A passkey assertion
    case PASSKEY = 'passkey';

    // A result an external identity provider verified
    case EXTERNAL_PROVIDER = 'external_provider';

    // The application's own account recovery: a first factor only
    case RECOVERY = 'recovery';

    // A channel the method did not name
    case UNKNOWN = 'unknown';
}
