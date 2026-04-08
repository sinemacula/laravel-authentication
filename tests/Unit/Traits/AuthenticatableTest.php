<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Traits\Authenticatable;

/**
 * Unit tests for the package Authenticatable trait.
 *
 * Marked `#[CoversNothing]` so phpunit does not attribute the
 * trait's runtime behaviour to a single concrete class — the
 * trait's real consumers carry their own coverage via the
 * integration suites.
 *
 * @internal
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
#[CoversNothing]
final class AuthenticatableTest extends TestCase
{
    /**
     * The remember-token name is zeroed out for the stateless package.
     *
     * @return void
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
     *
     * @return void
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
     *
     * @return void
     */
    public function testGetAuthPasswordNameDelegatesToLaravelTrait(): void
    {
        $consumer = new class extends Model {
            use Authenticatable;
        };

        self::assertSame('password', $consumer->getAuthPasswordName());
    }
}
