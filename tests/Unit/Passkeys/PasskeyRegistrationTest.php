<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Passkeys\Enums\PasskeyRegistrationStatus;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyRegistration;
use SineMacula\Laravel\Authentication\Passkeys\PasskeySummary;

/**
 * Unit tests for how registering a passkey ends.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasskeyRegistration::class)]
final class PasskeyRegistrationTest extends TestCase
{
    /**
     * A registered passkey carries its summary.
     *
     * @return void
     */
    public function testARegistrationCarriesThePasskey(): void
    {
        $createdAt    = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);
        $passkey      = new PasskeySummary('0192f6b2-0000-7000-8000-000000000001', 'Laptop', ['internal'], null, true, true, $createdAt, null);
        $registration = PasskeyRegistration::registered($passkey);

        self::assertTrue($registration->isRegistered());
        self::assertSame(PasskeyRegistrationStatus::REGISTERED, $registration->status);
        self::assertSame($passkey, $registration->passkey);
    }

    /**
     * A refused registration carries its status and no passkey.
     *
     * @return void
     */
    public function testARefusedRegistrationCarriesOnlyItsStatus(): void
    {
        $refusals = [
            PasskeyRegistrationStatus::CHALLENGE_INVALID->value  => PasskeyRegistration::challengeInvalid(),
            PasskeyRegistrationStatus::RESPONSE_INVALID->value   => PasskeyRegistration::responseInvalid(),
            PasskeyRegistrationStatus::ALREADY_REGISTERED->value => PasskeyRegistration::alreadyRegistered(),
        ];

        foreach ($refusals as $status => $registration) {
            self::assertFalse($registration->isRegistered());
            self::assertSame($status, $registration->status->value);
            self::assertNull($registration->passkey);
        }
    }

    /**
     * Registrations are made only through their named constructors.
     *
     * @return void
     */
    public function testTheConstructorIsPrivate(): void
    {
        self::assertTrue((new \ReflectionMethod(PasskeyRegistration::class, '__construct'))->isPrivate());
    }
}
