<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingRequirement;
use SineMacula\Laravel\Authentication\Sessions\Enums\SessionStatus;

/**
 * Unit tests for the values a pending session is described by: its status, what
 * it waits on, and the actions its credential may be used for.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PendingRequirement::class)]
final class PendingRequirementTest extends TestCase
{
    /**
     * A session is active or pending, stored by these values.
     *
     * @return void
     */
    public function testTheStatusesAreTheStoredValues(): void
    {
        self::assertSame(['active', 'pending'], array_map(static fn (SessionStatus $status): string => $status->value, SessionStatus::cases()));
    }

    /**
     * A pending session waits on a further factor, then a choice of principal,
     * in that order.
     *
     * @return void
     */
    public function testTheRequirementsAreTheReportedValuesInOrder(): void
    {
        self::assertSame(['mfa', 'principal'], array_map(static fn (PendingRequirement $requirement): string => $requirement->value, PendingRequirement::cases()));
    }

    /**
     * The actions' stable names: the further-factor package's, prefixed `mfa.`,
     * then this package's own.
     *
     * @return void
     */
    public function testTheActionsAreTheSharedStableNames(): void
    {
        self::assertSame([
            'mfa.list_factors',
            'mfa.send_code',
            'mfa.verify',
            'mfa.start_bootstrap_enrollment',
            'mfa.confirm_bootstrap_enrollment',
            'list_principals',
            'choose_principal',
        ], array_map(static fn (PendingAction $action): string => $action->value, PendingAction::cases()));
    }

    /**
     * Each requirement allows its own actions, and every action belongs to
     * exactly one.
     *
     * @return void
     */
    public function testEachRequirementAllowsItsOwnActionsOnly(): void
    {
        self::assertSame([
            PendingAction::LIST_FACTORS,
            PendingAction::SEND_CODE,
            PendingAction::VERIFY,
            PendingAction::START_BOOTSTRAP_ENROLLMENT,
            PendingAction::CONFIRM_BOOTSTRAP_ENROLLMENT,
        ], PendingRequirement::MFA->actions());

        self::assertSame([PendingAction::LIST_PRINCIPALS, PendingAction::CHOOSE_PRINCIPAL], PendingRequirement::PRINCIPAL->actions());

        self::assertSame(PendingAction::cases(), [...PendingRequirement::MFA->actions(), ...PendingRequirement::PRINCIPAL->actions()]);
    }
}
