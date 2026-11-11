<?php

declare(strict_types = 1);

namespace Tests\Unit\Config;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Config\JwtGuards;
use Tests\Fixtures\Guards\ReplicaPasswordIdentity;
use Tests\Integration\Fixtures\IntegrationIdentity;
use Tests\Integration\Fixtures\PasswordIdentity;
use Tests\Integration\Fixtures\PasswordMachine;

/**
 * Unit tests for listing the configured `jwt` guards and those that can return
 * an identity.
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
     * configured order.
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
     * The guards for an identity are those whose provider reads its table on
     * its connection or names no model.
     *
     * @return void
     */
    public function testTheGuardsForAnIdentityAreThoseWhoseProviderCanReturnIt(): void
    {
        $config = new Repository([
            'database' => ['default' => 'testing'],
            'auth'     => [
                'guards' => [
                    'plain'    => ['driver' => 'jwt', 'provider' => 'plain'],
                    'web'      => ['driver' => 'jwt', 'provider' => 'passwords'],
                    'custom'   => ['driver' => 'jwt', 'provider' => 'custom'],
                    'session'  => ['driver' => 'session', 'provider' => 'passwords'],
                    'machines' => ['driver' => 'jwt', 'provider' => 'machines'],
                    'replica'  => ['driver' => 'jwt', 'provider' => 'replica'],
                    'unknown'  => ['driver' => 'jwt', 'provider' => 'missing'],
                ],
                'providers' => [
                    'plain'     => ['driver' => 'model', 'model' => IntegrationIdentity::class],
                    'passwords' => ['driver' => 'model', 'model' => PasswordIdentity::class],
                    'custom'    => ['driver' => 'custom'],
                    'machines'  => ['driver' => 'model', 'model' => PasswordMachine::class],
                    'replica'   => ['driver' => 'model', 'model' => ReplicaPasswordIdentity::class],
                ],
            ],
        ]);

        self::assertSame(['web', 'custom', 'machines', 'unknown'], JwtGuards::namesFor(new PasswordIdentity, $config));
        self::assertSame(['plain', 'custom', 'unknown'], JwtGuards::namesFor(new IntegrationIdentity, $config));
        self::assertSame(['custom', 'replica', 'unknown'], JwtGuards::namesFor((new PasswordIdentity)->setConnection('replica'), $config));
        self::assertSame(['web', 'custom', 'machines', 'unknown'], JwtGuards::namesFor((new PasswordIdentity)->setConnection('testing'), $config));
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
