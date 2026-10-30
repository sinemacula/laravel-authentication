<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\PasswordResetLinkSender;
use SineMacula\Laravel\Authentication\Passwords\PasswordResetLink;
use SineMacula\Laravel\Authentication\Testing\FakePasswordResetLinkSender;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Unit tests for the password reset link sender fake tests bind in place of the
 * application's sender.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakePasswordResetLinkSender::class)]
final class FakePasswordResetLinkSenderTest extends TestCase
{
    /**
     * Restore the global container.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Container::setInstance(null);

        parent::tearDown();
    }

    /**
     * `fake()` binds a fresh instance as the sender in the container given, or
     * in the global container when none is, and returns it.
     *
     * @return void
     */
    public function testFakeBindsAFreshInstanceAsTheSender(): void
    {
        $given = new Container;
        $fake  = FakePasswordResetLinkSender::fake($given);

        self::assertSame($fake, $given->make(PasswordResetLinkSender::class));

        $global = new Container;

        Container::setInstance($global);

        $other = FakePasswordResetLinkSender::fake();

        self::assertSame($other, $global->make(PasswordResetLinkSender::class));
        self::assertNotSame($fake, $other);
    }

    /**
     * Every link is kept, oldest first, and can be filtered, counted and
     * forgotten; the last token for an identifier is the latest link's.
     *
     * @return void
     */
    public function testKeepsEveryLinkInOrder(): void
    {
        $fake   = new FakePasswordResetLinkSender;
        $first  = self::link('ada@example.test', 'first-token');
        $second = self::link('grace@example.test', 'second-token', 'admin');
        $third  = self::link('ada@example.test', 'third-token');

        self::assertSame([], $fake->sent());
        self::assertFalse($fake->hasSent());
        self::assertNull($fake->lastTokenFor('ada@example.test'));

        foreach ([$first, $second, $third] as $link) {
            $fake->send($link);
        }

        $admin = static fn (PasswordResetLink $link): bool => $link->guard === 'admin';
        $none  = static fn (PasswordResetLink $link): bool => $link->guard === 'console';

        self::assertSame([$first, $second, $third], $fake->sent());
        self::assertSame([$second], $fake->sent($admin));
        self::assertTrue($fake->hasSent($admin));
        self::assertFalse($fake->hasSent($none));
        self::assertSame(3, $fake->count());
        self::assertSame('third-token', $fake->lastTokenFor('ada@example.test'));
        self::assertSame('second-token', $fake->lastTokenFor('grace@example.test'));
        self::assertNull($fake->lastTokenFor('nobody@example.test'));

        $fake->forget();

        self::assertSame([0, []], [$fake->count(), $fake->sent()]);
    }

    /**
     * A link to the identifier with the token.
     *
     * @param  string  $identifier
     * @param  string  $token
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Passwords\PasswordResetLink
     */
    private static function link(string $identifier, string $token, string $guard = 'web'): PasswordResetLink
    {
        return new PasswordResetLink($guard, 'email', $identifier, $token, CarbonImmutable::createStrict(2026, 10, 29, 10, 30, 0), new PlainIdentityFixture(1));
    }
}
