<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Events\Enums\AuthenticationFlow;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;

/**
 * Unit tests for the failure and revocation enums: the values listeners and the
 * device row store, and which reasons a sign-in method may give.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FailureReason::class)]
final class FailureReasonTest extends TestCase
{
    /**
     * The failure reasons, in order, with the values listeners count.
     *
     * @return void
     */
    public function testFailureReasonsAreTheReportedValues(): void
    {
        self::assertSame([
            'invalid_credentials',
            'method_not_allowed',
            'rate_limited',
            'account_rate_limited',
            'identity_unknown',
            'identity_inactive',
            'principal_unresolved',
            'principal_mismatch',
            'principal_inactive',
            'tenant_inactive',
            'principal_ineligible',
            'identifier_unverified',
            'device_mismatch',
            'additional_factor_required',
            'additional_factor_failed',
            'principal_choice_abandoned',
            'pending_invalid',
            'token_invalid',
            'issued_before_cutoff',
            'device_unknown',
            'device_guard_mismatch',
            'device_revoked',
            'session_expired',
            'device_principal_mismatch',
            'rotation_reuse',
            'rotation_conflict',
            'refresh_key_missing',
            'refresh_token_conflict',
            'cross_site_request',
        ], array_map(static fn (FailureReason $reason): string => $reason->value, FailureReason::cases()));
    }

    /**
     * Only `invalid_credentials` is a reason a sign-in method may give; every
     * other one is the session service's to decide.
     *
     * @return void
     */
    public function testOnlyInvalidCredentialsIsASignInMethodReason(): void
    {
        $allowed = array_values(array_filter(FailureReason::cases(), static fn (FailureReason $reason): bool => $reason->isSignInMethodReason()));

        self::assertSame([FailureReason::INVALID_CREDENTIALS], $allowed);
    }

    /**
     * The flows a failure is reported for.
     *
     * @return void
     */
    public function testFlowsAreTheReportedValues(): void
    {
        $flows = array_map(static fn (AuthenticationFlow $flow): string => $flow->value, AuthenticationFlow::cases());

        self::assertSame(['sign_in', 'bearer', 'refresh', 'principal_switch'], $flows);
    }

    /**
     * The revocation reasons, in order, with the values stored on the device
     * row.
     *
     * @return void
     */
    public function testRevocationReasonsAreTheStoredValues(): void
    {
        self::assertSame([
            'rotation_reuse',
            'signed_out',
            'signed_out_everywhere',
            'revoked',
            'password_changed',
            'password_reset',
            'factor_removed',
            'identity_deactivated',
            'principal_deactivated',
            'tenant_deactivated',
        ], array_map(static fn (RevocationReason $reason): string => $reason->value, RevocationReason::cases()));
    }
}
