<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched when a refresh-token exchange fails for any reason.
 *
 * Carries a short machine-readable `reason` code so SIEM / audit-log
 * consumers can count failure modes (token_invalid, device_unknown,
 * rotation_mismatch, identity_inactive, principal_inactive,
 * principal_unresolved, authenticatable_missing) without scraping
 * log messages.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
final class RefreshFailed
{
    /** @var string Reason: the token could not be decoded, was expired, had the wrong `typ`, or failed iss/aud checks. */
    public const string REASON_TOKEN_INVALID = 'token_invalid';

    /** @var string Reason: the token's `did` claim did not resolve to any device row. */
    public const string REASON_DEVICE_UNKNOWN = 'device_unknown';

    /** @var string Reason: the token's rotation id did not hash-equal the device's stored digest. */
    public const string REASON_ROTATION_MISMATCH = 'rotation_mismatch';

    /** @var string Reason: the device's `authenticatable` relation did not resolve to an Identity. */
    public const string REASON_AUTHENTICATABLE_MISSING = 'authenticatable_missing';

    /** @var string Reason: the resolved identity reported `isActive() === false`. */
    public const string REASON_IDENTITY_INACTIVE = 'identity_inactive';

    /** @var string Reason: the principal resolver returned `null` for the identity. */
    public const string REASON_PRINCIPAL_UNRESOLVED = 'principal_unresolved';

    /** @var string Reason: the resolved principal reported `isActive() === false`. */
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

        /** Machine-readable failure reason — one of the REASON_* constants. */
        public string $reason,

        /** Device identifier from the token, when the token was parseable enough to yield one. */
        public ?string $deviceId = null,

    ) {}
}
