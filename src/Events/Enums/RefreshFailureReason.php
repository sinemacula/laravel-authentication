<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events\Enums;

/**
 * Machine-readable failure reason carried on a `RefreshFailed` event.
 *
 * Backed enum so SIEM consumers count failure modes without scraping log
 * messages, and every dispatch site gets compile-time protection against typo'd
 * reason strings.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum RefreshFailureReason: string
{
    // Token decode/expiry/missing claim/typ/guard/iss/aud failure
    case TOKEN_INVALID = 'token_invalid';

    // Device id is not a key of the device model or names no device
    case DEVICE_UNKNOWN = 'device_unknown';

    // Rotation id did not match the stored digest
    case ROTATION_MISMATCH = 'rotation_mismatch';

    // CAS lost: replay or concurrent rotation; device revoked
    case ROTATION_REUSE = 'rotation_reuse';

    // Device row marked revoked
    case DEVICE_REVOKED = 'device_revoked';

    // Device's idle or absolute deadline reached, or missing
    case SESSION_EXPIRED = 'session_expired';

    // Guard's identity provider did not return the device owner
    case AUTHENTICATABLE_MISSING = 'authenticatable_missing';

    // Resolved identity reported inactive
    case IDENTITY_INACTIVE = 'identity_inactive';

    // Principal resolver returned null
    case PRINCIPAL_UNRESOLVED = 'principal_unresolved';

    // Resolved principal does not match the refresh token pid hint
    case PRINCIPAL_MISMATCH = 'principal_mismatch';

    // Resolved principal reported inactive
    case PRINCIPAL_INACTIVE = 'principal_inactive';

    // Tenant the resolved principal acts within reported inactive, or opts into
    // activation and cannot be loaded
    case TENANT_INACTIVE = 'tenant_inactive';
}
