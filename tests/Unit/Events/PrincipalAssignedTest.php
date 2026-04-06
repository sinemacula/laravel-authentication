<?php

declare(strict_types=1);

namespace Tests\Unit\Events;

use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Events\PrincipalAssigned;

/**
 * PrincipalAssigned event unit tests.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversNothing]
final class PrincipalAssignedTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Asserts the event retains the guard name supplied at construction.
     *
     * @return void
     */
    public function testStoresGuardNameOnConstruction(): void
    {
        $principal = Mockery::mock(Principal::class);

        $event = new PrincipalAssigned('api', $principal);

        self::assertSame('api', $event->guard);
    }

    /**
     * Asserts the event retains the principal instance supplied at construction.
     *
     * @return void
     */
    public function testStoresPrincipalOnConstruction(): void
    {
        $principal = Mockery::mock(Principal::class);

        $event = new PrincipalAssigned('api', $principal);

        self::assertSame($principal, $event->principal);
    }
}
