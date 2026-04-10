<?php

declare(strict_types = 1);

namespace Tests\Unit\Traits;

use Illuminate\Database\Eloquent\Model;
use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Traits\Authenticatable;

/**
 * Unit tests for the package Authenticatable trait.
 *
 * The companion `#[CoversMethod]` attribute satisfies the
 * `php_unit_test_class_requires_covers` formatter rule (older
 * php-cs-fixer releases do not yet recognise the `CoversTrait`
 * attribute on its own). The `#[CoversTrait]` attribute is what
 * actually drives PHPUnit's coverage attribution for the trait.
 *
 * @internal
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
#[CoversMethod(Authenticatable::class, 'getRememberTokenName')]
#[CoversTrait(Authenticatable::class)]
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
     * The override returns `null` from `getRememberToken()` regardless
     * of any in-memory `remember_token` attribute, so the stateless
     * package never exposes a remember token to the framework.
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
     * `setRememberToken()` is an explicit no-op: passing it a value
     * does NOT mutate the model's attribute bag (no
     * `remember_token` key materialises).
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
