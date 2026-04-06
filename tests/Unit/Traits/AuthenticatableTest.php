<?php

declare(strict_types=1);

namespace Tests\Unit\Traits;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Traits\Authenticatable;

/**
 * Unit tests for the package Authenticatable trait.
 *
 * @internal
 *
 * @author    Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright 2026 Sine Macula Limited.
 */
#[CoversNothing]
final class AuthenticatableTest extends TestCase
{
    /**
     * The remember-token name is zeroed out for the stateless package.
     */
    public function testGetRememberTokenNameIsEmptyString(): void
    {
        $consumer = new class extends Model {
            use Authenticatable;
        };

        self::assertSame('', $consumer->getRememberTokenName());
    }

    /**
     * The trait inherits Laravel's default identifier column name.
     */
    public function testGetAuthIdentifierNameDelegatesToLaravelTrait(): void
    {
        $consumer = new class extends Model {
            use Authenticatable;
        };

        self::assertSame('id', $consumer->getAuthIdentifierName());
    }

    /**
     * The trait inherits Laravel's default password column name.
     */
    public function testGetAuthPasswordNameDelegatesToLaravelTrait(): void
    {
        $consumer = new class extends Model {
            use Authenticatable;
        };

        self::assertSame('password', $consumer->getAuthPasswordName());
    }
}
