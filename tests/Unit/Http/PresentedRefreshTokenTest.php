<?php

declare(strict_types = 1);

namespace Tests\Unit\Http;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * Unit tests for a refresh token presented from the body as plain values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PresentedRefreshToken::class)]
final class PresentedRefreshTokenTest extends TestCase
{
    /**
     * A string read from the body is presented from the body alone, as a
     * secret.
     *
     * @return void
     */
    public function testAStringIsPresentedFromTheBodyAlone(): void
    {
        $presented = PresentedRefreshToken::fromBody('a-refresh-token');

        self::assertSame('a-refresh-token', $presented->token->reveal());
        self::assertSame(RefreshTokenSource::BODY, $presented->source);
        self::assertSame([RefreshTokenSource::BODY], $presented->carriers);
    }

    /**
     * A secret read from the body is presented as it is, from the body alone.
     *
     * @return void
     */
    public function testASecretIsPresentedAsItIs(): void
    {
        $secret    = new Secret('a-refresh-token');
        $presented = PresentedRefreshToken::fromBody($secret);

        self::assertSame($secret, $presented->token);
        self::assertSame(RefreshTokenSource::BODY, $presented->source);
        self::assertSame([RefreshTokenSource::BODY], $presented->carriers);
    }

    /**
     * An empty token is refused before anything is presented.
     *
     * @return void
     */
    public function testAnEmptyTokenIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        PresentedRefreshToken::fromBody('');
    }
}
