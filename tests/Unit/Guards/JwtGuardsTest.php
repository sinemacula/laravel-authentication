<?php

declare(strict_types = 1);

namespace Tests\Unit\Guards;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Guards\JwtGuards;

/**
 * Unit tests for the listing of the configured `jwt` guards, which the helpers
 * that act for every guard (a new password, a changed identifier) read.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(JwtGuards::class)]
final class JwtGuardsTest extends TestCase
{
    /**
     * Only guards configured with the `jwt` driver are listed, in their
     * configured order and by name, a name of digits included; a guard of
     * another driver, one with no driver and a malformed entry are not.
     *
     * @return void
     */
    public function testOnlyTheJwtGuardsAreListed(): void
    {
        $config = new Repository(['auth' => ['guards' => [
            'web'     => ['driver' => 'jwt'],
            'session' => ['driver' => 'session'],
            'keys'    => ['driver' => 'api_key'],
            'bare'    => [],
            'broken'  => 'jwt',
            2024      => ['driver' => 'jwt'],
            'admin'   => ['driver' => 'jwt'],
        ]]]);

        self::assertSame(['web', '2024', 'admin'], JwtGuards::names($config));
    }

    /**
     * No guards, or guards that are not a list of them, list none.
     *
     * @return void
     */
    public function testNoGuardsListNone(): void
    {
        self::assertSame([], JwtGuards::names(new Repository));
        self::assertSame([], JwtGuards::names(new Repository(['auth' => ['guards' => 'jwt']])));
    }

    /**
     * The listing cannot be instantiated: it is a utility container only.
     *
     * @return void
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(JwtGuards::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);

        self::assertInstanceOf(JwtGuards::class, $instance);
    }
}
