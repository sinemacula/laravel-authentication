<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * Unit tests for the TokenPair value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TokenPair::class)]
final class TokenPairTest extends TestCase
{
    /**
     * Constructor stores the access and refresh tokens on the public
     * properties.
     *
     * @return void
     */
    public function testConstructorStoresAccessAndRefreshTokens(): void
    {
        $access  = new Secret('access-token');
        $refresh = new Secret('refresh-token');
        $result  = new TokenPair($access, $refresh);

        self::assertSame($access, $result->accessToken);
        self::assertSame($refresh, $result->refreshToken);
    }
}
