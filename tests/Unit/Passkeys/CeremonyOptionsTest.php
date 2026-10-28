<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Passkeys\CeremonyOptions;

/**
 * Unit tests for what a client is handed to run a passkey ceremony.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CeremonyOptions::class)]
final class CeremonyOptionsTest extends TestCase
{
    /**
     * The array and JSON forms give the challenge id, the options as they are,
     * and the expiry in ISO-8601.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheArrayAndJsonFormsCarryTheChallengeTheOptionsAndTheExpiry(): void
    {
        $expires = CarbonImmutable::createStrict(2026, 4, 6, 12, 5, 0);
        $options = new CeremonyOptions('0192f6b2-0000-7000-8000-000000000001', ['challenge' => 'abc', 'rpId' => 'example.test'], $expires);

        $expected = [
            'challenge'  => '0192f6b2-0000-7000-8000-000000000001',
            'options'    => ['challenge' => 'abc', 'rpId' => 'example.test'],
            'expires_at' => '2026-04-06T12:05:00+00:00',
        ];

        self::assertSame($expected, $options->toArray());
        self::assertSame($expected, json_decode(json_encode($options, JSON_THROW_ON_ERROR), true, flags: JSON_THROW_ON_ERROR));
    }
}
