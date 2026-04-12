<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt;

use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Jwt\RefreshResult;

/**
 * Unit tests for the RefreshResult value object.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 *
 * @internal
 */
final class RefreshResultTest extends TestCase
{
    /**
     * Constructor stores the access and refresh tokens on the public
     * properties.
     *
     * @return void
     */
    public function testConstructorStoresAccessAndRefreshTokens(): void
    {
        $result = new RefreshResult('access-token', 'refresh-token');

        self::assertSame('access-token', $result->accessToken);
        self::assertSame('refresh-token', $result->refreshToken);
    }
}
