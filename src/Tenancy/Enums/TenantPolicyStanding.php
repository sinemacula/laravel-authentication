<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Tenancy\Enums;

/**
 * How a session stands against its tenant's authentication policy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
enum TenantPolicyStanding: string
{
    // The session meets the policy
    case MET = 'met';

    // The session lacks the further factor the policy requires
    case FACTOR_REQUIRED = 'factor_required';

    // The session was not established through a connection the policy names
    case SSO_REQUIRED = 'sso_required';
}
