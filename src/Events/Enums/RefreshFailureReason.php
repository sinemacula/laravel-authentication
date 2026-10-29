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

    // Too many failed refreshes for the device or from the IP address; the
    // request is answered with 429
    case RATE_LIMITED = 'rate_limited';

    // Device id is not a key of the device model or names no device
    case DEVICE_UNKNOWN = 'device_unknown';

    // Device belongs to another guard's sessions, or to none; not revoked
    case DEVICE_GUARD_MISMATCH = 'device_guard_mismatch';

    // A rotated refresh token was presented: neither the current rotation id
    // nor the previous one inside the grace window; device revoked
    case ROTATION_REUSE = 'rotation_reuse';

    // The device's security state changed while the token was being rotated and
    // the token is still the current one; the client may retry
    case ROTATION_CONFLICT = 'rotation_conflict';

    // Device holds no refresh credential, so a replay cannot be told apart;
    // not revoked
    case REFRESH_KEY_MISSING = 'refresh_key_missing';

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

    // The guard no longer lets the method that started the session start its
    // sessions, or the device records no method; not revoked
    case METHOD_NOT_ALLOWED = 'method_not_allowed';

    // The guard's audience policy no longer admits the identity as the
    // principal; not revoked
    case PRINCIPAL_INELIGIBLE = 'principal_ineligible';
}
