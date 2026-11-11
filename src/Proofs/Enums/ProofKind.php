<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Proofs\Enums;

/**
 * What a proof recorded on a session proved.
 *
 * The first four values are the further-factor package's own, so an adapter
 * maps one onto the other by value.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ProofKind: string
{
    // The first factor a sign-in verified
    case FIRST_FACTOR = 'first_factor';

    // The first factor proved again on an active session
    case FIRST_FACTOR_REAUTHENTICATION = 'first_factor_reauthentication';

    // A further factor an adapter verified, at sign-in or as a step-up
    case ADDITIONAL_FACTOR = 'additional_factor';

    // A recovery code an adapter accepted in place of a further factor
    case RECOVERY_CODE = 'recovery_code';

    // A reauthentication at the external provider the session began with
    case EXTERNAL_REAUTHENTICATION = 'external_reauthentication';

    /**
     * Whether the kind is a further factor or its recovery-code fallback.
     *
     * @return bool
     */
    public function isAdditional(): bool
    {
        return $this === self::ADDITIONAL_FACTOR || $this === self::RECOVERY_CODE;
    }

    /**
     * Whether the kind proves the first factor again on an active session.
     *
     * @return bool
     */
    public function isReauthentication(): bool
    {
        return $this === self::FIRST_FACTOR_REAUTHENTICATION || $this === self::EXTERNAL_REAUTHENTICATION;
    }
}
