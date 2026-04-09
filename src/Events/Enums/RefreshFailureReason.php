<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events\Enums;

/**
 * Machine-readable failure reason carried on a `RefreshFailed` event.
 *
 * Backed enum so SIEM / audit-log consumers can count failure modes without
 * scraping log messages, and so every callsite that dispatches the event gets
 * compile-time protection against typo'd reason strings.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
enum RefreshFailureReason: string
{
    /** Token decode/expiry/typ/iss/aud failure. */
    case TOKEN_INVALID = 'token_invalid';

    /** Device id did not resolve. */
    case DEVICE_UNKNOWN = 'device_unknown';

    /** Rotation id did not match the device's stored digest. */
    case ROTATION_MISMATCH = 'rotation_mismatch';

    /** CAS lost: replay or concurrent rotation; device family revoked. */
    case ROTATION_REUSE = 'rotation_reuse';

    /** Device row marked revoked. */
    case DEVICE_REVOKED = 'device_revoked';

    /** Device authenticatable relation missing. */
    case AUTHENTICATABLE_MISSING = 'authenticatable_missing';

    /** Resolved identity reported inactive. */
    case IDENTITY_INACTIVE = 'identity_inactive';

    /** Principal resolver returned null. */
    case PRINCIPAL_UNRESOLVED = 'principal_unresolved';

    /** Resolved principal reported inactive. */
    case PRINCIPAL_INACTIVE = 'principal_inactive';
}
