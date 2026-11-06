<?php

declare(strict_types = 1);

namespace Tests\Unit\Passkeys;

use Carbon\CarbonImmutable;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Passkeys\NoPasskeyFactors;
use SineMacula\Laravel\Authentication\Passkeys\RegisteredPasskey;
use SineMacula\Laravel\Authentication\Proofs\ObservedProperties;
use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * Unit tests for the default passkey factor gate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NoPasskeyFactors::class)]
final class NoPasskeyFactorsTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Without a factor package no passkey is a factor: a registration is
     * associated with nothing, and a removal goes ahead completing nothing, the
     * identity never consulted.
     *
     * @return void
     */
    public function testNoPasskeyIsAFactor(): void
    {
        $identity = \Mockery::mock(Identity::class);
        $gate     = new NoPasskeyFactors;
        $passkey  = new RegisteredPasskey('0192f6b2-0000-7000-8000-000000000001', 'Y3JlZGVudGlhbA', 'example.test', new ObservedProperties, CarbonImmutable::now());

        $client = new ClientContext('203.0.113.7', 'agent');

        $identity->shouldNotReceive('getAuthIdentifier');

        self::assertNull($gate->registering($identity, 'api', $passkey, null, 'Laptop', $client, null));
        self::assertNull($gate->registering($identity, 'api', $passkey, null, 'Laptop', $client, new Secret('key.secret')));

        self::assertNull($gate->removing($identity, 'api', $passkey->id, $passkey->credentialId, $client));
    }
}
