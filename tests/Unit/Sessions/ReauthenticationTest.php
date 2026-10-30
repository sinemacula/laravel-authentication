<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Carbon\Carbon;
use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use Tests\Unit\Stubs\PlainDeviceFixture;

/**
 * Unit tests for the proofs of a recent authentication: each kind hands its
 * value to its own callback only, and a password never shows in a dump and
 * cannot be serialised.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Reauthentication::class)]
final class ReauthenticationTest extends TestCase
{
    /**
     * A device proof hands its device to the device callback.
     *
     * @return void
     */
    public function testADeviceProofCarriesItsDevice(): void
    {
        $device = new PlainDeviceFixture('device-1');

        self::assertSame(['device', $device], self::kind(Reauthentication::device($device)));
    }

    /**
     * A password proof hands its password to the password callback.
     *
     * @return void
     */
    public function testAPasswordProofCarriesItsPassword(): void
    {
        self::assertSame(['password', 'correct horse'], self::kind(Reauthentication::password('correct horse')));
    }

    /**
     * A confirmation carries its time as an immutable copy, so changing the
     * time it was built from changes nothing.
     *
     * @return void
     */
    public function testAConfirmationCarriesAnImmutableTime(): void
    {
        $at    = Carbon::parse('2027-03-01 08:30:00');
        $proof = Reauthentication::confirmedAt($at);

        $at->addHour();

        [$kind, $carried] = self::kind($proof);

        self::assertSame('confirmed', $kind);
        self::assertInstanceOf(CarbonImmutable::class, $carried);
        self::assertSame('2027-03-01 08:30:00', $carried->format('Y-m-d H:i:s'));
    }

    /**
     * No dump of a password proof shows the password, and it cannot be
     * serialised.
     *
     * @return void
     */
    public function testThePasswordIsNeverExposed(): void
    {
        $proof = Reauthentication::password('correct horse');

        self::assertStringNotContainsString('correct horse', print_r($proof, true));
        self::assertStringNotContainsString('correct horse', var_export($proof, true));

        $this->expectException(\Exception::class);

        serialize($proof);
    }

    /**
     * Which callback the proof ran, and with what.
     *
     * @param  \SineMacula\Laravel\Authentication\Sessions\Reauthentication  $proof
     * @return array{0: string, 1: mixed}
     */
    private static function kind(Reauthentication $proof): array
    {
        return $proof->apply(
            static fn (Device $device): array => ['device', $device],
            static fn (string $password): array => ['password', $password],
            static fn (CarbonImmutable $at): array => ['confirmed', $at],
        );
    }
}
