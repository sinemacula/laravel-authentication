<?php

declare(strict_types = 1);

namespace Tests\Unit\Jwt\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Jwt\Enums\Claims;

/**
 * Unit tests for the wire names of the `Claims` enum.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Claims::class)]
final class ClaimsTest extends TestCase
{
    /**
     * Every claim keeps its wire name: the session a token names is still the
     * `did` claim, though the case says what it names.
     *
     * @return void
     */
    public function testEveryClaimKeepsItsWireName(): void
    {
        self::assertSame('did', Claims::SESSION_ID->value);
        self::assertSame(
            ['sub', 'iss', 'aud', 'iat', 'exp', 'jti', 'typ', 'pid', 'did', 'grd', 'cid', 'scope'],
            array_map(static fn (Claims $claim): string => $claim->value, Claims::cases()),
        );
    }
}
