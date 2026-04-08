<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched when a refresh-token exchange fails. Carries a short
 * machine-readable `reason` code so SIEM / audit-log consumers can
 * count failure modes without scraping log messages.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class RefreshFailed
{
    /** @var string Token decode/expiry/typ/iss/aud failure. */
    public const string REASON_TOKEN_INVALID = 'token_invalid';

    /** @var string Device id did not resolve. */
    public const string REASON_DEVICE_UNKNOWN = 'device_unknown';

    /** @var string Rotation id did not match digest. */
    public const string REASON_ROTATION_MISMATCH = 'rotation_mismatch';

    /** @var string CAS lost: replay/concurrent rotation; family revoked. */
    public const string REASON_ROTATION_REUSE = 'rotation_reuse';

    /** @var string Device row marked revoked. */
    public const string REASON_DEVICE_REVOKED = 'device_revoked';

    /** @var string Device authenticatable relation missing. */
    public const string REASON_AUTHENTICATABLE_MISSING = 'authenticatable_missing';

    /** @var string Resolved identity reported inactive. */
    public const string REASON_IDENTITY_INACTIVE = 'identity_inactive';

    /** @var string Principal resolver returned null. */
    public const string REASON_PRINCIPAL_UNRESOLVED = 'principal_unresolved';

    /** @var string Resolved principal reported inactive. */
    public const string REASON_PRINCIPAL_INACTIVE = 'principal_inactive';

    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  string  $reason
     * @param  ?string  $deviceId
     */
    public function __construct(

        /** Name of the guard that attempted the refresh. */
        public string $guard,

        /** Machine-readable failure reason; one of REASON_*. */
        public string $reason,

        /** Device identifier from the token, when parseable. */
        public ?string $deviceId = null,

    ) {}
}
