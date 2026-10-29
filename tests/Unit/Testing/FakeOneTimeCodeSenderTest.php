<?php

declare(strict_types = 1);

namespace Tests\Unit\Testing;

use Carbon\CarbonImmutable;
use Illuminate\Container\Container;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage;
use SineMacula\Laravel\Authentication\Contracts\OneTimeCodeSender;
use SineMacula\Laravel\Authentication\Testing\FakeOneTimeCodeSender;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Unit tests for the one-time code sender fake tests bind in place of the
 * application's sender.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FakeOneTimeCodeSender::class)]
final class FakeOneTimeCodeSenderTest extends TestCase
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
        $fake  = FakeOneTimeCodeSender::fake($given);

        self::assertSame($fake, $given->make(OneTimeCodeSender::class));

        $global = new Container;

        Container::setInstance($global);

        $other = FakeOneTimeCodeSender::fake();

        self::assertSame($other, $global->make(OneTimeCodeSender::class));
        self::assertNotSame($fake, $other);
        self::assertSame($fake, $given->make(OneTimeCodeSender::class));
    }

    /**
     * Every message is kept, oldest first, and can be filtered, counted and
     * forgotten.
     *
     * @return void
     */
    public function testKeepsEveryMessageInOrder(): void
    {
        $fake   = new FakeOneTimeCodeSender;
        $first  = self::message('+447700900123', '111111');
        $second = self::message('ada@example.test', '222222', CodePurpose::VERIFY_IDENTIFIER);

        self::assertSame([], $fake->sent());
        self::assertFalse($fake->hasSent());
        self::assertSame(0, $fake->count());

        $fake->send($first);
        $fake->send($second);

        $verifications = static fn (OneTimeCodeMessage $message): bool => $message->purpose === CodePurpose::VERIFY_IDENTIFIER;
        $none          = static fn (OneTimeCodeMessage $message): bool => $message->guard === 'web';

        self::assertSame([$first, $second], $fake->sent());
        self::assertSame([$second], $fake->sent($verifications));
        self::assertSame([], $fake->sent($none));
        self::assertTrue($fake->hasSent());
        self::assertTrue($fake->hasSent($verifications));
        self::assertFalse($fake->hasSent($none));
        self::assertSame(2, $fake->count());

        $fake->forget();

        self::assertSame([], $fake->sent());
        self::assertSame(0, $fake->count());
    }

    /**
     * The last code sent to an identifier is the latest one's, for the purpose
     * when one is given; none when nothing was sent to it.
     *
     * @return void
     */
    public function testTheLastCodeForAnIdentifier(): void
    {
        $fake = new FakeOneTimeCodeSender;

        $fake->send(self::message('+447700900123', '111111'));
        $fake->send(self::message('+447700900123', '222222', CodePurpose::VERIFY_IDENTIFIER));
        $fake->send(self::message('+447700900999', '333333'));
        $fake->send(self::message('+447700900123', '444444'));

        self::assertSame('444444', $fake->lastCodeFor('+447700900123'));
        self::assertSame('444444', $fake->lastCodeFor('+447700900123', CodePurpose::SIGN_IN));
        self::assertSame('222222', $fake->lastCodeFor('+447700900123', CodePurpose::VERIFY_IDENTIFIER));
        self::assertSame('333333', $fake->lastCodeFor('+447700900999'));
        self::assertNull($fake->lastCodeFor('+447700900000'));
        self::assertNull($fake->lastCodeFor('+447700900999', CodePurpose::VERIFY_IDENTIFIER));
    }

    /**
     * A message to the identifier with the code and purpose.
     *
     * @param  string  $identifier
     * @param  string  $code
     * @param  \SineMacula\Laravel\Authentication\Codes\Enums\CodePurpose  $purpose
     * @return \SineMacula\Laravel\Authentication\Codes\OneTimeCodeMessage
     */
    private static function message(string $identifier, string $code, CodePurpose $purpose = CodePurpose::SIGN_IN): OneTimeCodeMessage
    {
        return new OneTimeCodeMessage('mobile', $purpose, 'phone', $identifier, $code, CarbonImmutable::createStrict(2026, 4, 6, 12, 10, 0), new PlainIdentityFixture(1));
    }
}
