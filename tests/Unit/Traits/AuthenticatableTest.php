<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Traits\Authenticatable;

/**
 * Unit tests for the package Authenticatable trait.
 *
 * Exercises the public trait surface through anonymous Eloquent models without
 * relying on explicit PHPUnit coverage metadata for traits.
 *
 * @internal
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[\PHPUnit\Framework\Attributes\CoversNothing]
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

    /**
     * The override returns `null` from `getRememberToken()` regardless of any
     * in-memory `remember_token` attribute, so the stateless package never
     * exposes a remember token to the framework.
     *
     * @return void
     */
    public function testGetRememberTokenIsNull(): void
    {
        $consumer = new class extends Model {
            use Authenticatable;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $consumer->setRawAttributes(['remember_token' => 'should-be-ignored']);

        self::assertNull($consumer->getRememberToken());
    }

    /**
     * `setRememberToken()` is an explicit no-op: passing it a value does NOT
     * mutate the model's attribute bag (no `remember_token` key materialises).
     *
     * @return void
     */
    public function testSetRememberTokenIsNoOp(): void
    {
        $consumer = new class extends Model {
            use Authenticatable;

            /** @var array<string> Mass-assignment guard list. */
            protected $guarded = [];
        };

        $consumer->setRememberToken('should-not-be-stored');

        self::assertNull($consumer->getAttribute('remember_token'));
        self::assertSame([], $consumer->getAttributes());
    }
}
