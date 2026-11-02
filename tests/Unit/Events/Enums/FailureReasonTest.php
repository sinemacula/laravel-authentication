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
 * session row store, and which reasons a sign-in method may give.
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
            'tenant_ineligible',
            'principal_ineligible',
            'sso_required',
            'identifier_unverified',
            'session_mismatch',
            'additional_factor_required',
            'pending_invalid',
            'pending_action_not_allowed',
            'session_pending',
            'token_invalid',
            'issued_before_cutoff',
            'session_unknown',
            'session_guard_mismatch',
            'session_revoked',
            'session_expired',
            'session_principal_mismatch',
            'session_tenant_mismatch',
            'session_switched',
            'rotation_reuse',
            'rotation_conflict',
            'refresh_key_missing',
            'refresh_token_conflict',
            'refresh_transport_mismatch',
            'cross_site_request',
            'code_expired',
            'code_exhausted',
            'passkey_challenge_invalid',
            'passkey_counter_regressed',
            'machine_identity',
            'credential_invalid',
            'credential_revoked',
            'credential_expired',
            'credential_guard_mismatch',
            'scope_invalid',
            'reauthentication_required',
            'identifier_taken',
            'link_expired',
            'proof_invalid',
            'proof_binding_mismatch',
            'step_up_required',
            'deliveries_exhausted',
            'factor_code_locked',
            'factor_code_refused',
        ], array_map(static fn (FailureReason $reason): string => $reason->value, FailureReason::cases()));
    }

    /**
     * The reasons a sign-in method may give: a refused input, an identifier the
     * input proved possession of but that is not verified, and the code and
     * passkey outcomes; every other one is the session service's to decide.
     *
     * @return void
     */
    public function testTheSignInMethodReasons(): void
    {
        $allowed = array_values(array_filter(FailureReason::cases(), static fn (FailureReason $reason): bool => $reason->isSignInMethodReason()));

        self::assertSame([
            FailureReason::INVALID_CREDENTIALS,
            FailureReason::IDENTIFIER_UNVERIFIED,
            FailureReason::CODE_EXPIRED,
            FailureReason::CODE_EXHAUSTED,
            FailureReason::PASSKEY_CHALLENGE_INVALID,
            FailureReason::PASSKEY_COUNTER_REGRESSED,
        ], $allowed);
    }

    /**
     * The reasons only the server-side event carries, so a sign-in's result
     * reveals neither an account nor a code, and a reset's result says an
     * expired link is invalid.
     *
     * @return void
     */
    public function testTheConcealedReasons(): void
    {
        $concealed = array_values(array_filter(FailureReason::cases(), static fn (FailureReason $reason): bool => $reason->isConcealed()));

        self::assertSame([
            FailureReason::ACCOUNT_RATE_LIMITED,
            FailureReason::CODE_EXPIRED,
            FailureReason::CODE_EXHAUSTED,
            FailureReason::PASSKEY_COUNTER_REGRESSED,
            FailureReason::LINK_EXPIRED,
        ], $concealed);
    }

    /**
     * The flows a failure is reported for.
     *
     * @return void
     */
    public function testFlowsAreTheReportedValues(): void
    {
        $flows = array_map(static fn (AuthenticationFlow $flow): string => $flow->value, AuthenticationFlow::cases());

        self::assertSame([
            'sign_in',
            'bearer',
            'refresh',
            'switch',
            'sign_out',
            'code_request',
            'identifier_verification',
            'api_key',
            'client_credentials',
            'password_reset',
            'identifier_change',
            'step_up',
            'reauthentication',
            'factor_code',
        ], $flows);
    }

    /**
     * The revocation reasons, in order, with the values stored on the session
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
            'superseded',
            'password_changed',
            'password_reset',
            'factor_removed',
            'identity_deactivated',
            'principal_deactivated',
            'tenant_deactivated',
            'tenant_policy_changed',
        ], array_map(static fn (RevocationReason $reason): string => $reason->value, RevocationReason::cases()));
    }
}
