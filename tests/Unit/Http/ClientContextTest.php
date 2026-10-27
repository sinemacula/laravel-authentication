<?php

declare(strict_types = 1);

namespace Tests\Unit\Http;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Http\ClientContext;

/**
 * Unit tests for the client context, read from a request or built from raw
 * values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClientContext::class)]
final class ClientContextTest extends TestCase
{
    /**
     * Rows of `[remote address, stored IP address]`.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideRemoteAddresses(): iterable
    {
        yield from [
            'IPv4'                   => ['203.0.113.7', '203.0.113.7'],
            'IPv6'                   => ['2001:db8::1', '2001:db8::1'],
            'longest, 45 characters' => ['0000:0000:0000:0000:0000:ffff:255.255.255.255', '0000:0000:0000:0000:0000:ffff:255.255.255.255'],
            'not an address'         => ['not-an-ip', null],
            'address with a port'    => ['203.0.113.7:443', null],
            'empty'                  => ['', null],
            'missing'                => [null, null],
        ];
    }

    /**
     * Only a valid IPv4 or IPv6 address is kept; anything else is `null`.
     *
     * @param  ?string  $remoteAddress
     * @param  ?string  $expected
     * @return void
     */
    #[DataProvider('provideRemoteAddresses')]
    public function testKeepsOnlyAValidIpAddress(?string $remoteAddress, ?string $expected): void
    {
        $server = $remoteAddress === null ? [] : ['REMOTE_ADDR' => $remoteAddress];

        $request = Request::create('/', 'GET', [], [], [], $server);

        if ($remoteAddress === null) {
            $request->server->remove('REMOTE_ADDR');
        }

        self::assertSame($expected, ClientContext::fromRequest($request)->ip);
    }

    /**
     * Rows of `[user agent header, stored user agent]`.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideUserAgents(): iterable
    {
        yield from [
            'plain'                       => ['Mozilla/5.0', 'Mozilla/5.0'],
            'NUL bytes removed'           => ["Mozilla\0/5.0\0", 'Mozilla/5.0'],
            'invalid UTF-8 replaced'      => ["Agent \xC3\x28 \xFF", 'Agent ?( ?'],
            'exactly 512 characters'      => [str_repeat('é', 512), str_repeat('é', 512)],
            'over 512 characters cut'     => [str_repeat('é', 513), str_repeat('é', 512)],
            'cut after cleaning, by char' => ["\0" . str_repeat('日', 600), str_repeat('日', 512)],
            'empty'                       => ['', null],
            'only NUL bytes'              => ["\0\0", null],
            'missing'                     => [null, null],
        ];
    }

    /**
     * A user agent is stored without NUL bytes, as valid UTF-8, and at most 512
     * characters long (not bytes); one that is empty after cleaning is `null`.
     *
     * @param  ?string  $header
     * @param  ?string  $expected
     * @return void
     */
    #[DataProvider('provideUserAgents')]
    public function testCleansTheUserAgent(?string $header, ?string $expected): void
    {
        $server = $header === null ? [] : ['HTTP_USER_AGENT' => $header];

        $request = Request::create('/', 'GET', [], [], [], $server);

        if ($header === null) {
            $request->headers->remove('User-Agent');
        }

        self::assertSame($expected, ClientContext::fromRequest($request)->userAgent);
    }

    /**
     * An IP address handed to the constructor is kept only when it is valid, as
     * one read from a request is, so no instance holds an unsafe one.
     *
     * @param  ?string  $ip
     * @param  ?string  $expected
     * @return void
     */
    #[DataProvider('provideRemoteAddresses')]
    public function testConstructorKeepsOnlyAValidIpAddress(?string $ip, ?string $expected): void
    {
        self::assertSame($expected, (new ClientContext($ip, null))->ip);
    }

    /**
     * A user agent handed to the constructor is cleaned as one read from a
     * request is, so no instance holds an unsafe one.
     *
     * @param  ?string  $userAgent
     * @param  ?string  $expected
     * @return void
     */
    #[DataProvider('provideUserAgents')]
    public function testConstructorCleansTheUserAgent(?string $userAgent, ?string $expected): void
    {
        self::assertSame($expected, (new ClientContext(null, $userAgent))->userAgent);
    }

    /**
     * Any client-supplied value is cleaned to the length asked for, counted in
     * characters, with NUL bytes removed and invalid UTF-8 replaced, and
     * nothing left reads as `null`.
     *
     * @return void
     */
    public function testCleanTextCutsToTheGivenLengthInCharacters(): void
    {
        self::assertSame('Pixé', ClientContext::cleanText("Pi\0xé 9", 4));
        self::assertSame('ab?', ClientContext::cleanText("ab\xC3", 3));
        self::assertNull(ClientContext::cleanText("\0\0", 4));
        self::assertNull(ClientContext::cleanText(null, 4));
    }
}
