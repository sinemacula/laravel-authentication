<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Context\Enums;

/**
 * The package's own keys of an authentication context, as the dot paths `get()`
 * and `has()` take.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum AuthenticationKey: string
{
    // Whether the identity is a person or a machine
    case SUBJECT_TYPE = 'authentication.subject_type';

    // The identity's morph class
    case IDENTITY_TYPE = 'authentication.identity_type';

    // The identity's auth identifier
    case IDENTITY_ID = 'authentication.identity_id';

    // The principal's morph class
    case PRINCIPAL_TYPE = 'authentication.principal_type';

    // The principal's identifier
    case PRINCIPAL_ID = 'authentication.principal_id';

    // The active tenant's morph class
    case TENANT_TYPE = 'authentication.tenant_type';

    // The active tenant's identifier
    case TENANT_ID = 'authentication.tenant_id';

    // The guard's name
    case APPLICATION = 'authentication.application';

    // The bound session's identifier
    case SESSION_ID = 'authentication.session_id';

    // The session's `amr` values
    case AMR = 'authentication.amr';

    // When the session's newest counting proof was made
    case AUTH_TIME = 'authentication.auth_time';

    // Whether an accepted additional verification is on the session
    case MFA = 'authentication.mfa';

    // Whether an accepted recovery code is on the session
    case RECOVERY_CODE = 'authentication.recovery_code';

    // Whether an accepted evaluation on the session reported multifactor
    case MULTIFACTOR = 'authentication.multifactor';

    // Seconds since the newest proof that set `mfa` or `recovery_code`
    case SECONDS_SINCE_STEP_UP = 'authentication.seconds_since_step_up';

    // The kind of credential the request presented
    case CREDENTIAL = 'authentication.credential';

    // The scopes the credential grants
    case SCOPES = 'authentication.scopes';

    // The client's IP address
    case IP = 'authentication.ip';

    /**
     * The type of the key's value when it is not `null`.
     *
     * @return \SineMacula\Laravel\Authentication\Context\Enums\ContextKeyType
     */
    public function type(): ContextKeyType
    {
        return match ($this) {
            self::AMR, self::SCOPES                           => ContextKeyType::LIST,
            self::AUTH_TIME                                   => ContextKeyType::TIME,
            self::SECONDS_SINCE_STEP_UP                       => ContextKeyType::NUMBER,
            self::MFA, self::RECOVERY_CODE, self::MULTIFACTOR => ContextKeyType::BOOL,
            self::IP                                          => ContextKeyType::IP,
            default                                           => ContextKeyType::STRING,
        };
    }
}
