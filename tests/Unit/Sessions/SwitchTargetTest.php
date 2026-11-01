<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Sessions\SwitchTarget;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;
use Tests\Unit\Stubs\PlainPrincipalFixture;

/**
 * Unit tests for where a switch takes a session.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SwitchTarget::class)]
final class SwitchTargetTest extends TestCase
{
    /**
     * A switch to a principal names it, in the tenant selected, or in no
     * selection, the principal's default.
     *
     * @return void
     */
    public function testAPrincipalTargetNamesThePrincipalAndItsTenant(): void
    {
        $principal = new PlainPrincipalFixture('p-1');
        $tenant    = TenantSelection::of('t-1');

        $named = SwitchTarget::principal($principal, $tenant);

        self::assertSame($principal, $named->principal);
        self::assertSame($tenant, $named->tenant);

        $default = SwitchTarget::principal($principal);

        self::assertSame($principal, $default->principal);
        self::assertNull($default->tenant);
    }

    /**
     * A switch of tenant keeps the session's principal: it names none.
     *
     * @return void
     */
    public function testATenantTargetNamesNoPrincipal(): void
    {
        $none   = TenantSelection::none();
        $target = SwitchTarget::tenant($none);

        self::assertNull($target->principal);
        self::assertSame($none, $target->tenant);
    }

    /**
     * Targets are made only through their named constructors.
     *
     * @return void
     */
    public function testTheConstructorIsPrivate(): void
    {
        self::assertTrue((new \ReflectionMethod(SwitchTarget::class, '__construct'))->isPrivate());
    }
}
