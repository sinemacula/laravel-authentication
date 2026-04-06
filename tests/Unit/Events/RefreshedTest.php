<?php

declare(strict_types=1);

namespace Tests\Unit\Events;

use Mockery;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Events\Refreshed;

/**
 * Refreshed event unit tests.
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 *
 * @internal
 */
#[CoversNothing]
final class RefreshedTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Asserts the event retains the guard name supplied at construction.
     *
     * @return void
     */
    public function testStoresGuardNameOnConstruction(): void
    {
        $identity = Mockery::mock(Identity::class);

        $event = new Refreshed('api', $identity);

        self::assertSame('api', $event->guard);
    }

    /**
     * Asserts the event retains the identity instance supplied at construction.
     *
     * @return void
     */
    public function testStoresIdentityOnConstruction(): void
    {
        $identity = Mockery::mock(Identity::class);

        $event = new Refreshed('api', $identity);

        self::assertSame($identity, $event->identity);
    }
}
