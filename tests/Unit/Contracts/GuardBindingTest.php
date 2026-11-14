<?php

declare(strict_types = 1);

namespace Tests\Unit\Contracts;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\GuardBinding;
use SineMacula\Laravel\Authentication\Contracts\Tenant;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * Shape tests for the guard's binds, each taking an optional client last.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class GuardBindingTest extends TestCase
{
    /**
     * Rows of `[the bind, its parameters in order]`.
     *
     * @return iterable<string, array{0: string, 1: list<string>}>
     */
    public static function provideBinds(): iterable
    {
        yield 'loginStarted' => ['loginStarted', ['identity', 'principal', 'session', 'client']];
        yield 'loginVerified' => ['loginVerified', ['identity', 'principal', 'session', 'tenant', 'method', 'client']];
        yield 'authenticateAs' => ['authenticateAs', ['identity', 'principal', 'session', 'scopes', 'tenant', 'client']];
    }

    /**
     * Each bind takes the client last, as an optional `ClientContext` that
     * defaults to `null`.
     *
     * @param  string  $bind
     * @param  list<string>  $parameters
     * @return void
     */
    #[DataProvider('provideBinds')]
    public function testEachBindTakesTheClientItsEventsDescribeLast(string $bind, array $parameters): void
    {
        $method = new \ReflectionMethod(GuardBinding::class, $bind);
        $names  = array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $method->getParameters());

        self::assertSame($parameters, $names);

        $client = $method->getParameters()[count($parameters) - 1];
        $type   = $client->getType();

        self::assertInstanceOf(\ReflectionNamedType::class, $type);
        self::assertSame(ClientContext::class, $type->getName());
        self::assertTrue($type->allowsNull());
        self::assertTrue($client->isDefaultValueAvailable());
        self::assertNull($client->getDefaultValue());
    }

    /**
     * `authenticateAs()` takes the destination tenant before the client, both
     * optional, so a switch binds in its destination tenant for its client.
     *
     * @return void
     */
    public function testAuthenticateAsTakesTheTenantBeforeTheClient(): void
    {
        $tenant = (new \ReflectionMethod(GuardBinding::class, 'authenticateAs'))->getParameters()[4];
        $type   = $tenant->getType();

        self::assertInstanceOf(\ReflectionNamedType::class, $type);
        self::assertSame(Tenant::class, $type->getName());
        self::assertTrue($tenant->isOptional());
    }
}
