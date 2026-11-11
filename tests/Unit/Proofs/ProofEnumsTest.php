<?php

declare(strict_types = 1);

namespace Tests\Unit\Proofs;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Proofs\Enums\ChannelKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\KeyProtection;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;
use SineMacula\Laravel\Authentication\Proofs\Enums\Purpose;

/**
 * Unit tests for the proof enum values and how the proof kinds are grouped.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProofKind::class)]
#[CoversClass(Purpose::class)]
#[CoversClass(ChannelKind::class)]
#[CoversClass(KeyProtection::class)]
final class ProofEnumsTest extends TestCase
{
    /**
     * The proof kinds, in order, with the values a proof records.
     *
     * @return void
     */
    public function testTheProofKindsAreTheRecordedValues(): void
    {
        self::assertSame(
            ['first_factor', 'first_factor_reauthentication', 'additional_factor', 'recovery_code', 'external_reauthentication'],
            array_map(static fn (ProofKind $kind): string => $kind->value, ProofKind::cases()),
        );
    }

    /**
     * Only a further factor and a recovery code are additional.
     *
     * @return void
     */
    public function testTheKindsAreGrouped(): void
    {
        $additional       = array_values(array_filter(ProofKind::cases(), static fn (ProofKind $kind): bool => $kind->isAdditional()));
        $reauthentication = array_values(array_filter(ProofKind::cases(), static fn (ProofKind $kind): bool => $kind->isReauthentication()));

        self::assertSame([ProofKind::ADDITIONAL_FACTOR, ProofKind::RECOVERY_CODE], $additional);
        self::assertSame([ProofKind::FIRST_FACTOR_REAUTHENTICATION, ProofKind::EXTERNAL_REAUTHENTICATION], $reauthentication);
    }

    /**
     * The purposes, channel kinds and key protections, in order, with their
     * values.
     *
     * @return void
     */
    public function testThePurposesChannelsAndKeyProtectionsAreTheRecordedValues(): void
    {
        self::assertSame(['sign_in', 'reauthenticate', 'step_up', 'enrollment'], array_map(static fn (Purpose $purpose): string => $purpose->value, Purpose::cases()));
        self::assertSame(
            ['password', 'sms', 'email', 'authenticator_app', 'passkey', 'external_provider', 'recovery', 'unknown'],
            array_map(static fn (ChannelKind $kind): string => $kind->value, ChannelKind::cases()),
        );
        self::assertSame(['hardware', 'software'], array_map(static fn (KeyProtection $protection): string => $protection->value, KeyProtection::cases()));
    }
}
