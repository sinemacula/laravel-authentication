<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions\Enums;

/**
 * What a pending session waits on: a further factor, then a choice of
 * principal, in that order, since the factor is asked of the identity before
 * any principal is chosen.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum PendingRequirement: string
{
    // A further factor, verified by the further-factor package
    case MFA = 'mfa';

    // A choice among the principals the identity may use the application as
    case PRINCIPAL = 'principal';

    /**
     * The actions a pending credential may be used for while this is the first
     * requirement outstanding.
     *
     * @return list<\SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction>
     */
    public function actions(): array
    {
        return match ($this) {
            self::MFA => [
                PendingAction::LIST_FACTORS,
                PendingAction::SEND_CODE,
                PendingAction::VERIFY,
                PendingAction::START_BOOTSTRAP_ENROLLMENT,
                PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT,
            ],
            self::PRINCIPAL => [PendingAction::LIST_PRINCIPALS, PendingAction::CHOOSE_PRINCIPAL],
        };
    }
}
