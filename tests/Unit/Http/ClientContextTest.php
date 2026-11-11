<?php

declare(strict_types = 1);

namespace Tests\Unit\Http;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use Symfony\Component\HttpFoundation\Exception\ConflictingHeadersException;
use Symfony\Component\HttpFoundation\Exception\SuspiciousOperationException;

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
     * Forget the trusted hosts and proxies a test set.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Request::setTrustedHosts([]);
        Request::setTrustedProxies([], 0);

        parent::tearDown();
    }

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
            'controls removed'            => ["Mozilla\u{001B}[2J/5.0\u{202E}\u{0085}", 'Mozilla[2J/5.0'],
            'controls never use the cut'  => ["\u{202E}\u{007F}" . str_repeat('a', 513), str_repeat('a', 512)],
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
     * A user agent is cleaned and cut to 512 characters; one left empty is
     * `null`.
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
     * An IP address handed to the constructor is kept only when it is valid.
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
     * request is.
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
     * A request's context holds its `Origin`, its scheme and host, and the
     * names of its non-empty headers.
     *
     * @return void
     */
    public function testReadsTheSameSiteFactsOfARequest(): void
    {
        $request = Request::create('https://api.example.test:8443/auth/sign-in', 'POST', server: [
            'HTTP_ORIGIN'           => 'https://app.example.test',
            'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest',
            'HTTP_X_REFRESH_TOKEN'  => 'secret-refresh-token',
            'HTTP_X_EMPTY'          => '',
        ]);

        $request->headers->set('X-Later', ['', 'second']);

        $client = ClientContext::fromRequest($request);

        self::assertSame('https://app.example.test', $client->origin);
        self::assertSame('https://api.example.test:8443', $client->schemeAndHost);
        self::assertContains('x-requested-with', $client->nonEmptyHeaders);
        self::assertContains('x-refresh-token', $client->nonEmptyHeaders);
        self::assertContains('origin', $client->nonEmptyHeaders);
        self::assertNotContains('x-empty', $client->nonEmptyHeaders);
        self::assertNotContains('x-later', $client->nonEmptyHeaders);
        self::assertSame(array_values(array_unique($client->nonEmptyHeaders)), $client->nonEmptyHeaders);
        self::assertStringNotContainsString('secret-refresh-token', serialize($client));
        self::assertTrue($client->carriesHeader('X-Requested-With'));
        self::assertTrue($client->carriesHeader('x_requested_with'));
        self::assertFalse($client->carriesHeader('X-Empty'));
        self::assertFalse($client->carriesHeader('X-Later'));
    }

    /**
     * A request without an `Origin` has none; its scheme and host are still
     * read.
     *
     * @return void
     */
    public function testARequestWithoutAnOriginHasNone(): void
    {
        $client = ClientContext::fromRequest(Request::create('/auth/sign-in', 'POST'));

        self::assertNull($client->origin);
        self::assertSame('http://localhost', $client->schemeAndHost);
        self::assertFalse($client->carriesHeader('X-Requested-With'));
    }

    /**
     * A host Symfony refuses leaves no scheme and host, and the request still
     * refuses it afterwards.
     *
     * @return void
     */
    public function testARefusedHostLeavesNoSchemeAndHost(): void
    {
        $request = Request::create('/auth/sign-in', 'POST', server: ['HTTP_ORIGIN' => 'http://bad!host']);

        $request->headers->set('Host', 'bad!host');

        $first  = ClientContext::fromRequest($request);
        $second = ClientContext::fromRequest($request);

        self::assertSame([null, null], [$first->schemeAndHost, $second->schemeAndHost]);
        self::assertSame('http://bad!host', $first->origin);

        $this->expectException(SuspiciousOperationException::class);

        $request->getHost();
    }

    /**
     * An untrusted host leaves no scheme and host, and the request still
     * refuses it afterwards.
     *
     * @return void
     */
    public function testAnUntrustedHostLeavesNoSchemeAndHost(): void
    {
        Request::setTrustedHosts(['^good\.example$']);

        $request = Request::create('http://evil.example/auth/sign-in', 'POST');

        $first  = ClientContext::fromRequest($request);
        $second = ClientContext::fromRequest($request);

        self::assertSame([null, null], [$first->schemeAndHost, $second->schemeAndHost]);

        $this->expectException(SuspiciousOperationException::class);

        $request->getHost();
    }

    /**
     * A request's same-site facts alone carry no IP address or user agent.
     *
     * @return void
     */
    public function testReadsTheSameSiteFactsAloneOfARequest(): void
    {
        $request = Request::create('https://api.example.test:8443/auth/sign-in', 'POST', server: [
            'REMOTE_ADDR'           => '203.0.113.7',
            'HTTP_USER_AGENT'       => 'Browser/1.0',
            'HTTP_ORIGIN'           => 'https://app.example.test',
            'HTTP_X_REQUESTED_WITH' => 'XMLHttpRequest',
        ]);

        $full  = ClientContext::fromRequest($request);
        $facts = ClientContext::sameSiteFactsOf($request);

        self::assertSame(['203.0.113.7', 'Browser/1.0'], [$full->ip, $full->userAgent]);
        self::assertSame([null, null], [$facts->ip, $facts->userAgent]);
        self::assertSame('https://app.example.test', $facts->origin);
        self::assertSame('https://api.example.test:8443', $facts->schemeAndHost);
        self::assertSame($full->nonEmptyHeaders, $facts->nonEmptyHeaders);
        self::assertContains('x-requested-with', $facts->nonEmptyHeaders);
    }

    /**
     * Reading the same-site facts leaves the IP address unread, so conflicting
     * forwarded addresses do not fail it.
     *
     * @return void
     */
    public function testSameSiteFactsLeaveForwardedAddressesUnread(): void
    {
        Request::setTrustedProxies(['10.0.0.1'], Request::HEADER_FORWARDED | Request::HEADER_X_FORWARDED_FOR);

        $request = Request::create('http://api.example.test/auth/sign-out', 'POST', server: [
            'REMOTE_ADDR'          => '10.0.0.1',
            'HTTP_FORWARDED'       => 'for=198.51.100.1',
            'HTTP_X_FORWARDED_FOR' => '198.51.100.2',
            'HTTP_ORIGIN'          => 'http://api.example.test',
        ]);

        $first  = ClientContext::sameSiteFactsOf($request);
        $second = ClientContext::sameSiteFactsOf($request);

        self::assertSame(['http://api.example.test', 'http://api.example.test'], [$first->schemeAndHost, $second->schemeAndHost]);
        self::assertNull($first->ip);

        $this->expectException(ConflictingHeadersException::class);

        $request->ip();
    }

    /**
     * Forwarded headers that disagree on the scheme leave no scheme and host.
     *
     * @return void
     */
    public function testConflictingForwardedHeadersLeaveNoSchemeAndHost(): void
    {
        Request::setTrustedProxies(['10.0.0.1'], Request::HEADER_FORWARDED | Request::HEADER_X_FORWARDED_PROTO);

        $request = Request::create('http://api.example.test/auth/sign-in', 'POST', server: [
            'REMOTE_ADDR'            => '10.0.0.1',
            'HTTP_FORWARDED'         => 'proto=https',
            'HTTP_X_FORWARDED_PROTO' => 'http',
        ]);

        $first  = ClientContext::fromRequest($request);
        $second = ClientContext::fromRequest($request);

        self::assertSame([null, null], [$first->schemeAndHost, $second->schemeAndHost]);

        $this->expectException(ConflictingHeadersException::class);

        $request->isSecure();
    }

    /**
     * A host already refused to the application leaves no scheme and host.
     *
     * @return void
     */
    public function testAHostAlreadyRefusedLeavesNoSchemeAndHost(): void
    {
        Request::setTrustedHosts(['^good\.example$']);

        $request = Request::create('http://evil.example:8080/auth/sign-in', 'POST');
        $refused = false;

        try {
            $request->getHost();
        } catch (SuspiciousOperationException) {
            $refused = true;
        }

        self::assertTrue($refused);
        self::assertNull(ClientContext::fromRequest($request)->schemeAndHost);
    }

    /**
     * A request with no host at all has no scheme and host.
     *
     * @return void
     */
    public function testARequestWithoutAHostHasNoSchemeAndHost(): void
    {
        self::assertNull(ClientContext::fromRequest(new Request)->schemeAndHost);
    }

    /**
     * Rows of `[origin given, origin kept]`.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideOrigins(): iterable
    {
        yield 'an origin' => ['https://app.example.test', 'https://app.example.test'];
        yield 'the opaque origin' => ['null', 'null'];
        yield 'exactly 512 characters' => [str_repeat('a', 512), str_repeat('a', 512)];
        yield 'over 512 characters, never cut' => [str_repeat('a', 513), null];
        yield 'a space' => ['https://app.example.test ', null];
        yield 'a control character' => [<<<'EOD'
            https://app.example.test

            EOD, null];
        yield 'beyond ASCII' => ['https://äpp.example.test', null];
        yield 'empty' => ['', null];
        yield 'missing' => [null, null];
    }

    /**
     * An origin, scheme and host are kept whole only when 1 to 512 printable
     * ASCII characters.
     *
     * @param  ?string  $origin
     * @param  ?string  $expected
     * @return void
     */
    #[DataProvider('provideOrigins')]
    public function testKeepsAnOriginOnlyWhenPrintableAsciiAndWhole(?string $origin, ?string $expected): void
    {
        $client = new ClientContext(null, null, $origin, $origin);

        self::assertSame([$expected, $expected], [$client->origin, $client->schemeAndHost]);

        $request = Request::create('/auth/sign-in', 'POST');

        if ($origin !== null) {
            $request->headers->set('Origin', $origin);
        }

        self::assertSame($expected, ClientContext::fromRequest($request)->origin);
    }

    /**
     * Header names given to the constructor are filed once each, and any that
     * is not an HTTP token is dropped.
     *
     * @return void
     */
    public function testFilesTheHeaderNamesItIsGiven(): void
    {
        $client = new ClientContext(null, null, null, null, ['X-Requested-With', 'x_requested_with', 'X-CSRF', "X-CSRF\n", 'not a token', '', 'a:b', 'key' => 'Accept']);

        self::assertSame(['x-requested-with', 'x-csrf', 'accept'], $client->nonEmptyHeaders);
    }

    /**
     * A context built from the IP address and user agent alone carries no
     * same-site facts.
     *
     * @return void
     */
    public function testTheTwoValueConstructorCarriesNoSameSiteFacts(): void
    {
        $client = new ClientContext('203.0.113.7', 'Browser/1.0');

        self::assertSame([null, null, []], [$client->origin, $client->schemeAndHost, $client->nonEmptyHeaders]);
        self::assertFalse($client->carriesHeader('X-Requested-With'));
    }
}
