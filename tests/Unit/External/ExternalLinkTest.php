<?php

declare(strict_types = 1);

namespace Tests\Unit\External;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\External\ExternalLink;
use Tests\Unit\Stubs\PlainIdentityFixture;

/**
 * Unit tests for a link the link contract finds.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ExternalLink::class)]
final class ExternalLinkTest extends TestCase
{
    /**
     * A link keeps its identity and its id exactly as given, up to 255
     * characters, not bytes.
     *
     * @return void
     */
    public function testKeepsTheIdentityAndTheIdExactly(): void
    {
        $identity = new PlainIdentityFixture(7);
        $link     = new ExternalLink($identity, 'Link-1 ');

        self::assertSame($identity, $link->identity);
        self::assertSame('Link-1 ', $link->id);
        self::assertSame(255, ExternalLink::ID_MAX_LENGTH);
        self::assertSame(str_repeat('é', 255), (new ExternalLink($identity, str_repeat('é', 255)))->id);
    }

    /**
     * Rows of `[id]` a link refuses: empty, or longer than 255 characters.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideRefusedIds(): iterable
    {
        yield from [
            'empty'    => [''],
            'too long' => [str_repeat('l', 256)],
        ];
    }

    /**
     * A link with an id that is empty or too long is refused.
     *
     * @param  string  $id
     * @return void
     */
    #[DataProvider('provideRefusedIds')]
    public function testRefusesAnIdThatDoesNotFit(string $id): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An external link\'s id must be from 1 to 255 characters.');

        new ExternalLink(new PlainIdentityFixture(7), $id);
    }
}
