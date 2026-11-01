<?php

declare(strict_types = 1);

namespace Tests\Unit\Factors;

use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Factors\NeverRequireAdditionalFactor;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * Unit tests for the default additional-factor policy and the context a policy
 * decides on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NeverRequireAdditionalFactor::class)]
#[CoversClass(AdditionalFactorContext::class)]
final class NeverRequireAdditionalFactorTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * The default never asks for a further factor, even for a sign-in from a
     * client it has never seen.
     *
     * @return void
     */
    public function testNeverRequiresAFurtherFactor(): void
    {
        $identity = \Mockery::mock(Identity::class);
        $context  = new AdditionalFactorContext('api', $identity, 'password', new ClientContext(null, null), null, null, null);

        self::assertFalse((new NeverRequireAdditionalFactor)->requiresAdditionalFactor($context));
    }

    /**
     * The context carries everything it was given, and names no principal or
     * tenant: the policy is asked about the identity, before any principal is
     * chosen.
     *
     * @return void
     */
    public function testContextCarriesTheSignIn(): void
    {
        $identity = \Mockery::mock(Identity::class);
        $session  = \Mockery::mock(Session::class);
        $client   = new ClientContext('203.0.113.7', 'agent');

        $context = new AdditionalFactorContext('api', $identity, 'sso', $client, 'Work laptop', 'macOS', $session);

        self::assertSame('api', $context->guard);
        self::assertSame($identity, $context->identity);
        self::assertSame(['guard', 'identity', 'method', 'client', 'clientName', 'platform', 'provenSession'], array_keys(get_object_vars($context)));
        self::assertSame('sso', $context->method);
        self::assertSame($client, $context->client);
        self::assertSame('Work laptop', $context->clientName);
        self::assertSame('macOS', $context->platform);
        self::assertSame($session, $context->provenSession);
    }
}
