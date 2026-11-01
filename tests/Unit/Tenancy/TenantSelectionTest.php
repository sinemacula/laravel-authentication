<?php

declare(strict_types = 1);

namespace Tests\Unit\Tenancy;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;

/**
 * Unit tests for the tenant a sign-in, a choice or a switch selects: the
 * principal's default, none, or one named by its opaque identifier.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TenantSelection::class)]
final class TenantSelectionTest extends TestCase
{
    /**
     * The principal's default names no tenant and says it is the default.
     *
     * @return void
     */
    public function testThePrincipalDefault(): void
    {
        $selection = TenantSelection::principalDefault();

        self::assertTrue($selection->isPrincipalDefault());
        self::assertNull($selection->tenantId());
    }

    /**
     * None names no tenant and is not the default, so a switch to it moves a
     * principal out of its own tenant rather than keeping it there.
     *
     * @return void
     */
    public function testNone(): void
    {
        $selection = TenantSelection::none();

        self::assertFalse($selection->isPrincipalDefault());
        self::assertNull($selection->tenantId());
    }

    /**
     * A tenant named by an integer or a string is carried as the string a
     * session records, up to the column's 255 characters, multibyte ones
     * counted as one.
     *
     * @return void
     */
    public function testANamedTenantIsCarriedAsAString(): void
    {
        $longest = str_repeat('é', TenantSelection::ID_MAX_LENGTH);

        self::assertSame('42', TenantSelection::of(42)->tenantId());
        self::assertSame('0', TenantSelection::of(0)->tenantId());
        self::assertSame('tenant-a', TenantSelection::of('tenant-a')->tenantId());
        self::assertSame($longest, TenantSelection::of($longest)->tenantId());
        self::assertFalse(TenantSelection::of('tenant-a')->isPrincipalDefault());
    }

    /**
     * Identifiers a session cannot record: empty, and longer than the column.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUnrecordableIdentifiers(): iterable
    {
        yield 'empty' => [''];
        yield 'one character too long' => [str_repeat('a', TenantSelection::ID_MAX_LENGTH + 1)];
    }

    /**
     * An identifier a session cannot record is refused when it is named.
     *
     * @param  string  $tenantId
     * @return void
     */
    #[DataProvider('provideUnrecordableIdentifiers')]
    public function testAnUnrecordableIdentifierIsRefused(string $tenantId): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A tenant identifier must be between 1 and 255 characters.');

        TenantSelection::of($tenantId);
    }
}
