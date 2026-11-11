<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;

/**
 * Unit tests for a registered passkey as the factor gate sees it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RegisteredPasskey::class)]
final class RegisteredPasskeyTest extends TestCase
{
    /**
     * It carries the row's id, the credential id, the relying party and what
     * was shown.
     *
     * @return void
     */
    public function testCarriesWhatTheRegistrationShowed(): void
    {
        $observed = new ObservedProperties(true, true, true, false, true);
        $at       = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);
        $passkey  = new RegisteredPasskey('0192f6b2-0000-7000-8000-000000000001', 'Y3JlZGVudGlhbA', 'example.test', $observed, $at);

        self::assertSame(['id', 'credentialId', 'rpId', 'observed', 'registeredAt'], array_keys(get_object_vars($passkey)));
        self::assertSame(['0192f6b2-0000-7000-8000-000000000001', 'Y3JlZGVudGlhbA', 'example.test'], [$passkey->id, $passkey->credentialId, $passkey->rpId]);
        self::assertSame($observed, $passkey->observed);
        self::assertSame($at, $passkey->registeredAt);
    }
}
