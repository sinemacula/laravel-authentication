<?php

declare(strict_types = 1);

namespace Tests\Unit\Factors;

use Carbon\CarbonImmutable;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Proofs\SignInProof;

/**
 * Unit tests for the context an additional-factor policy decides on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AdditionalFactorContext::class)]
final class AdditionalFactorContextTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * The context carries everything it was given, the first factor's whole
     * proof among it, and names no principal or tenant: the policy is asked
     * about the identity, before any principal is chosen.
     *
     * @return void
     */
    public function testCarriesTheSignIn(): void
    {
        $identity = \Mockery::mock(Identity::class);
        $session  = \Mockery::mock(Session::class);
        $client   = new ClientContext('203.0.113.7', 'agent');
        $first    = SignInProof::unattested('sso', CarbonImmutable::now())->recorded();

        $context = new AdditionalFactorContext('api', $identity, $first, $client, 'Work laptop', 'macOS', $session);

        self::assertSame(['application', 'identity', 'firstFactor', 'client', 'clientName', 'platform', 'provenSession'], array_keys(get_object_vars($context)));
        self::assertSame('api', $context->application);
        self::assertSame($identity, $context->identity);
        self::assertSame($first, $context->firstFactor);
        self::assertSame('sso', $context->firstFactor->method);
        self::assertSame($client, $context->client);
        self::assertSame('Work laptop', $context->clientName);
        self::assertSame('macOS', $context->platform);
        self::assertSame($session, $context->provenSession);
    }
}
