<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Illuminate\Http\Request;
use Mockery\Adapter\Phpunit\MockeryPHPUnitIntegration;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;

/**
 * Unit tests for the context of a sign-in: the client description it cleans,
 * and what it carries through.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInContext::class)]
final class SignInContextTest extends TestCase
{
    use MockeryPHPUnitIntegration;

    /**
     * Rows of `[given, stored]`: client descriptions and what is kept of them.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideDescriptions(): iterable
    {
        yield from [
            'absent'                         => [null, null],
            'empty'                          => ['', null],
            'only a NUL byte'                => ["\0", null],
            'plain'                          => ['Work laptop', 'Work laptop'],
            'NUL bytes removed'              => ["Work\0 laptop\0", 'Work laptop'],
            'invalid UTF-8 replaced'         => ["Lap \xC3\x28 \xFF", 'Lap ?( ?'],
            'whitespace kept'                => ['  spaced  ', '  spaced  '],
            '255 characters kept'            => [str_repeat('é', 255), str_repeat('é', 255)],
            'cut to 255 characters'          => [str_repeat('é', 256), str_repeat('é', 255)],
            'cut after cleaning, not before' => ["\0" . str_repeat('a', 255) . 'b', str_repeat('a', 255)],
        ];
    }

    /**
     * The client name and platform are made safe to store: NUL bytes removed,
     * invalid UTF-8 replaced, cut to 255 characters, and empty read as `null`.
     *
     * @param  ?string  $given
     * @param  ?string  $stored
     * @return void
     */
    #[DataProvider('provideDescriptions')]
    public function testTheClientDescriptionIsCleaned(?string $given, ?string $stored): void
    {
        $context = new SignInContext(new ClientContext(null, null), $given, $given);

        self::assertSame($stored, $context->clientName);
        self::assertSame($stored, $context->platform);
    }

    /**
     * The client, the principal and the refresh token are carried as given, and
     * default to none.
     *
     * @return void
     */
    public function testCarriesTheClientPrincipalAndRefreshToken(): void
    {
        $client    = new ClientContext('203.0.113.7', 'agent');
        $principal = \Mockery::mock(Principal::class);
        $context   = new SignInContext($client, principal: $principal, refreshToken: 'refresh-token');

        self::assertSame($client, $context->client);
        self::assertSame($principal, $context->principal);
        self::assertSame('refresh-token', $context->refreshToken);

        $bare = new SignInContext($client);

        self::assertNull($bare->clientName);
        self::assertNull($bare->platform);
        self::assertNull($bare->principal);
        self::assertNull($bare->refreshToken);
    }

    /**
     * Built from a request, the context reads the client from it, cleaned as
     * `ClientContext` cleans it, and cleans the description it is given.
     *
     * @return void
     */
    public function testFromRequestReadsTheClient(): void
    {
        $request   = Request::create('/sign-in', 'POST', server: ['REMOTE_ADDR' => '203.0.113.7', 'HTTP_USER_AGENT' => "Agent\0"]);
        $principal = \Mockery::mock(Principal::class);

        $context = SignInContext::fromRequest($request, "Phone\0", 'iOS', $principal, 'refresh-token');

        self::assertSame('203.0.113.7', $context->client->ip);
        self::assertSame('Agent', $context->client->userAgent);
        self::assertSame('Phone', $context->clientName);
        self::assertSame('iOS', $context->platform);
        self::assertSame($principal, $context->principal);
        self::assertSame('refresh-token', $context->refreshToken);

        $bare = SignInContext::fromRequest($request);

        self::assertNull($bare->clientName);
        self::assertNull($bare->refreshToken);
    }

    /**
     * The refresh token is a sensitive parameter, so a stack trace never shows
     * it.
     *
     * @return void
     */
    public function testTheRefreshTokenIsASensitiveParameter(): void
    {
        foreach ([new \ReflectionMethod(SignInContext::class, '__construct'), new \ReflectionMethod(SignInContext::class, 'fromRequest')] as $method) {

            $parameter = array_values(array_filter($method->getParameters(), static fn (\ReflectionParameter $parameter): bool => $parameter->getName() === 'refreshToken'))[0];

            self::assertNotEmpty($parameter->getAttributes(\SensitiveParameter::class));
        }
    }
}
