<?php

declare(strict_types = 1);

namespace Tests\Unit\Factors;

use Carbon\CarbonImmutable;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Factors\AdditionalFactorContext;
use SineMacula\Laravel\Authentication\Factors\NeverRequireAdditionalFactor;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Tests\Fixtures\Proofs\UndescribedSignInProof;

/**
 * Unit tests for the default additional-factor policy.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(NeverRequireAdditionalFactor::class)]
final class NeverRequireAdditionalFactorTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * The default asks for nothing beyond the first factor, even of a sign-in
     * from a client it has never seen: its requirement is empty, so the feature
     * is off until a policy that asks for more is bound.
     *
     * @return void
     */
    public function testRequiresNothingBeyondTheFirstFactor(): void
    {
        $first   = UndescribedSignInProof::of('password', CarbonImmutable::now())->recorded();
        $context = new AdditionalFactorContext('api', \Mockery::mock(Identity::class), $first, new ClientContext(null, null), null, null, null);

        $requirement = (new NeverRequireAdditionalFactor)->requirementFor($context);

        self::assertTrue($requirement->isEmpty());
        self::assertSame([], $requirement->kinds());
    }
}
