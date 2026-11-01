<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Database\SessionRetention;
use Tests\TestCase;

/**
 * Feature tests for the session retention pruning and `authentication:check`
 * both read: 30 days unless configured, the boundaries accepted, and anything
 * else refused with the same message.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SessionRetention::class)]
final class SessionRetentionTest extends TestCase
{
    /**
     * With nothing configured the retention is 30 days.
     *
     * @return void
     */
    public function testDefaultsToThirtyDays(): void
    {
        config()->set('authentication.session', ['model' => 'unused']);

        self::assertSame(30, SessionRetention::days());
    }

    /**
     * The boundaries are accepted, as integers and as the digit strings `env()`
     * returns, and read when asked.
     *
     * @return void
     */
    public function testReadsTheBoundariesWhenAsked(): void
    {
        config()->set('authentication.session.prune_after_days', '0');

        self::assertSame(0, SessionRetention::days());

        config()->set('authentication.session.prune_after_days', 3650);

        self::assertSame(3650, SessionRetention::days());
    }

    /**
     * A retention past the boundaries is refused.
     *
     * @return void
     */
    public function testRefusesARetentionPastTheBoundaries(): void
    {
        config()->set('authentication.session.prune_after_days', '3651');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('authentication.session.prune_after_days must be an integer from 0 to 3650.');

        SessionRetention::days();
    }

    /**
     * `SessionRetention` is a static utility; instantiation is disallowed
     * through the private constructor. Reflection invokes it so the line is
     * covered while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(SessionRetention::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);
    }
}
