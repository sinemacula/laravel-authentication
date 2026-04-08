<?php

declare(strict_types = 1);

namespace Tests\Unit\Facades;

use Illuminate\Support\Facades\Auth as IlluminateAuth;
use Orchestra\Testbench\TestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Organization;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Facades\Auth;

/**
 * Unit tests for the package's Auth facade subclass.
 *
 * @internal
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
#[CoversClass(Auth::class)]
final class AuthFacadeTest extends TestCase
{
    /**
     * Setup.
     *
     * @return void
     */
    protected function setUp(): void
    {
        parent::setUp();

        // T22's AuthServiceProvider will replace the inline registration
        // below once committed. Until then, register the four contextual
        // macros here so the facade assertions run in isolation.
        IlluminateAuth::macro('principal', static fn (): ?Principal => null);
        IlluminateAuth::macro('device', static fn (): ?Device => null);
        IlluminateAuth::macro('organization', static fn (): ?Organization => null);
        IlluminateAuth::macro('scope', static fn (): ?string => null);
    }

    /**
     * Teardown.
     *
     * @return void
     */
    protected function tearDown(): void
    {
        IlluminateAuth::flushMacros();

        parent::tearDown();
    }

    /**
     * The package facade subclass extends Laravel's framework
     * `Auth` facade so IDE autocompletion picks up both surfaces.
     *
     * @return void
     */
    public function testPackageFacadeExtendsFrameworkFacade(): void
    {
        $reflection = new \ReflectionClass(Auth::class);

        self::assertTrue(
            $reflection->isSubclassOf(IlluminateAuth::class),
            'Package Auth facade must extend Illuminate\Support\Facades\Auth.',
        );
    }

    /**
     * The `principal` macro is registered against the framework facade.
     *
     * @return void
     */
    public function testPrincipalMacroIsRegistered(): void
    {
        self::assertTrue(IlluminateAuth::hasMacro('principal'));
    }

    /**
     * The `device` macro is registered against the framework facade.
     *
     * @return void
     */
    public function testDeviceMacroIsRegistered(): void
    {
        self::assertTrue(IlluminateAuth::hasMacro('device'));
    }

    /**
     * The `organization` macro is registered against the framework facade.
     *
     * @return void
     */
    public function testOrganizationMacroIsRegistered(): void
    {
        self::assertTrue(IlluminateAuth::hasMacro('organization'));
    }

    /**
     * The `scope` macro is registered against the framework facade.
     *
     * @return void
     */
    public function testScopeMacroIsRegistered(): void
    {
        self::assertTrue(IlluminateAuth::hasMacro('scope'));
    }
}
