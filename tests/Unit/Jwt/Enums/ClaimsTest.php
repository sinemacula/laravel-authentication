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
     * Every claim keeps its wire name, in order.
     *
     * @return void
     */
    public function testEveryClaimKeepsItsWireName(): void
    {
        self::assertSame(
            ['iss', 'aud', 'sub', 'sub_type', 'client_id', 'principal', 'sid', 'tenant_id', 'auth_time', 'amr', 'jti', 'iat', 'exp', 'cid', 'scope'],
            array_map(static fn (Claims $claim): string => $claim->value, Claims::cases()),
        );
    }
}
