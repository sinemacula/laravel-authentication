<?php

declare(strict_types = 1);

namespace Tests\Unit\Http;

use Carbon\CarbonImmutable;
use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Http\Enums\Transport;
use SineMacula\Laravel\Authentication\Http\PresentedRefreshToken;
use SineMacula\Laravel\Authentication\Http\RefreshTokenSettings;
use SineMacula\Laravel\Authentication\Http\RefreshTokenTransport;
use SineMacula\Laravel\Authentication\Jwt\TokenPair;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\Exception\ConflictingHeadersException;
use Tests\Unit\Stubs\PlainSessionFixture;

/**
 * Unit tests for extracting, judging and delivering an application's refresh
 * token.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshTokenTransport::class)]
#[CoversClass(PresentedRefreshToken::class)]
final class RefreshTokenTransportTest extends TestCase
{
    /** @var string A refresh token, as opaque to the transport as any other value. */
    private const string TOKEN = 'header.payload.signature';

    /** @var string The application's refresh cookie. */
    private const string COOKIE = '__Secure-refresh_token';

    /** @var string An origin the application allows besides the request's own. */
    private const string ALLOWED_ORIGIN = 'https://app.example.test';

    /**
     * Forget the trusted proxies a test set.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        Request::setTrustedProxies([], 0);

        parent::tearDown();
    }

    /**
     * A request that carries no token presents nothing, by either transport.
     *
     * @return void
     */
    public function testARequestWithoutATokenPresentsNothing(): void
    {
        self::assertNull(self::transport()->extract(Request::create('/auth/refresh', 'POST')));
        self::assertNull(self::transport(Transport::COOKIE)->extract(Request::create('/auth/refresh', 'POST')));
        self::assertNull(self::transport()->extract(Request::create('/auth/refresh', 'POST')));
        self::assertNull(self::transport(Transport::COOKIE)->extract(Request::create('/auth/refresh', 'POST')));
    }

    /**
     * Rows of `[the request, the source it carries the token in]`.
     *
     * @return iterable<string, array{0: \Closure(): \Illuminate\Http\Request, 1: \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource}>
     */
    public static function provideCarriedTokens(): iterable
    {
        yield 'a JSON body' => [static fn (): Request => self::json(['refresh_token' => self::TOKEN]), RefreshTokenSource::BODY];
        yield 'a form body' => [static fn (): Request => Request::create('/auth/refresh', 'POST', ['refresh_token' => self::TOKEN]), RefreshTokenSource::BODY];
        yield 'a header' => [static fn (): Request => self::withHeaders(['X-Refresh-Token' => self::TOKEN]), RefreshTokenSource::HEADER];
        yield 'the cookie from the own origin' => [static fn (): Request => self::cookie(self::TOKEN, 'http://localhost', 'XMLHttpRequest'), RefreshTokenSource::COOKIE];
        yield 'the cookie from an allowed origin' => [static fn (): Request => self::cookie(self::TOKEN, self::ALLOWED_ORIGIN, 'fetch'), RefreshTokenSource::COOKIE];
    }

    /**
     * A token in the transport's one carrier is extracted as a secret, with
     * that carrier.
     *
     * @param  \Closure(): \Illuminate\Http\Request  $request
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @return void
     */
    #[DataProvider('provideCarriedTokens')]
    public function testATokenByTheApplicationsTransportIsPresentedWithIt(\Closure $request, RefreshTokenSource $source): void
    {
        $transport = self::transport($source === RefreshTokenSource::COOKIE ? Transport::COOKIE : Transport::BODY);

        $presented = $transport->extract($request());

        self::assertInstanceOf(PresentedRefreshToken::class, $presented);
        self::assertInstanceOf(Secret::class, $presented->token);
        self::assertSame(self::TOKEN, $presented->token->reveal());
        self::assertSame($source, $presented->source);
        self::assertSame([$source], $presented->carriers);
    }

    /**
     * A token extracted from a same-site request passes the judgement with its
     * client.
     *
     * @param  \Closure(): \Illuminate\Http\Request  $request
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @return void
     */
    #[DataProvider('provideCarriedTokens')]
    public function testAnExtractedTokenPassesTheJudgement(\Closure $request, RefreshTokenSource $source): void
    {
        $transport = self::transport($source === RefreshTokenSource::COOKIE ? Transport::COOKIE : Transport::BODY);
        $sent      = $request();

        self::assertNull($transport->judge(self::presented($transport->extract($sent)), ClientContext::fromRequest($sent)));
    }

    /**
     * Rows of `[the request]` that carry the token only where no application
     * reads one.
     *
     * @return iterable<string, array{0: \Closure(): \Illuminate\Http\Request}>
     */
    public static function provideUnreadPlaces(): iterable
    {
        yield 'the query string of a POST' => [static fn (): Request => Request::create('/auth/refresh?refresh_token=' . self::TOKEN, 'POST')];
        yield 'the query string of a GET' => [static fn (): Request => Request::create('/auth/refresh', 'GET', ['refresh_token' => self::TOKEN])];
        yield 'the form body of a GET' => [static fn (): Request => self::formBody('GET')];
        yield 'the form body of a HEAD' => [static fn (): Request => self::formBody('HEAD')];
        yield 'another body field' => [static fn (): Request => self::json(['token' => self::TOKEN])];
        yield 'another application\'s cookie' => [static fn (): Request => Request::create('/auth/refresh', 'POST', [], ['__Secure-other_refresh_token' => self::TOKEN])];
    }

    /**
     * A token where no application reads one is not presented, by either
     * transport.
     *
     * @param  \Closure(): \Illuminate\Http\Request  $request
     * @return void
     */
    #[DataProvider('provideUnreadPlaces')]
    public function testATokenWhereNoApplicationReadsIsNotPresented(\Closure $request): void
    {
        self::assertNull(self::transport()->extract($request()));
        self::assertNull(self::transport(Transport::COOKIE)->extract($request()));
        self::assertNull(self::transport()->extract($request()));
        self::assertNull(self::transport(Transport::COOKIE)->extract($request()));
    }

    /**
     * A body application without a header reads the body field only.
     *
     * @return void
     */
    public function testABodyApplicationWithoutAHeaderReadsTheBodyFieldOnly(): void
    {
        $transport = self::transport(Transport::BODY, null);

        self::assertNull($transport->extract(self::withHeaders(['X-Refresh-Token' => self::TOKEN])));
        self::assertNull($transport->extract(self::withHeaders(['X-Refresh-Token' => self::TOKEN])));
        self::assertSame(RefreshTokenSource::BODY, self::presented($transport->extract(self::json(['refresh_token' => self::TOKEN], ['X-Refresh-Token' => self::TOKEN])))->source);
        self::assertSame(RefreshTokenSource::BODY, self::presented($transport->extract(self::json(['refresh_token' => self::TOKEN], ['X-Refresh-Token' => self::TOKEN])))->source);
    }

    /**
     * Rows of `[the request, the transport]` that carry a token in more than
     * one carrier.
     *
     * @return iterable<string, array{0: \Closure(): \Illuminate\Http\Request, 1: \SineMacula\Laravel\Authentication\Http\Enums\Transport}>
     */
    public static function provideConflicts(): iterable
    {
        yield 'the same token in the body and a header' => [
            static fn (): Request => self::json(['refresh_token' => self::TOKEN], ['X-Refresh-Token' => self::TOKEN]),
            Transport::BODY,
        ];
        yield 'different tokens in the body and a header' => [
            static fn (): Request => self::json(['refresh_token' => self::TOKEN], ['X-Refresh-Token' => 'other']),
            Transport::BODY,
        ];
        yield 'an empty header beside the body' => [static fn (): Request => self::json(['refresh_token' => self::TOKEN], ['X-Refresh-Token' => '']), Transport::BODY];
        yield 'the cookie and the body, to a body application' => [
            static fn (): Request => self::cookie(self::TOKEN, 'http://localhost', 'XMLHttpRequest', ['refresh_token' => self::TOKEN]),
            Transport::BODY,
        ];
        yield 'the cookie and the body, to a cookie application' => [
            static fn (): Request => self::cookie(self::TOKEN, 'http://localhost', 'XMLHttpRequest', ['refresh_token' => self::TOKEN]),
            Transport::COOKIE,
        ];
        yield 'the cookie and a header, to a cookie application' => [static function (): Request {
            $request = self::cookie(self::TOKEN, 'http://localhost', 'XMLHttpRequest');
            $request->headers->set('X-Refresh-Token', self::TOKEN);

            return $request;
        }, Transport::COOKIE];
        yield 'the cookie and the body, sent cross-site' => [static fn (): Request => self::cookie(self::TOKEN, null, null, ['refresh_token' => self::TOKEN]), Transport::COOKIE];
    }

    /**
     * A token in more than one carrier is a conflict, before the cross-site
     * checks.
     *
     * @param  \Closure(): \Illuminate\Http\Request  $request
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\Transport  $transport
     * @return void
     */
    #[DataProvider('provideConflicts')]
    public function testATokenInMoreThanOneCarrierIsAConflict(\Closure $request, Transport $transport): void
    {
        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, self::transport($transport)->extract($request()));
        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, self::transport($transport)->extract($request()));
    }

    /**
     * Rows of `[the request, the transport]` that carry one token by another
     * transport.
     *
     * @return iterable<string, array{0: \Closure(): \Illuminate\Http\Request, 1: \SineMacula\Laravel\Authentication\Http\Enums\Transport}>
     */
    public static function provideMismatches(): iterable
    {
        yield 'the cookie, to a body application' => [static fn (): Request => self::cookie(self::TOKEN, 'http://localhost', 'XMLHttpRequest'), Transport::BODY];
        yield 'the cookie sent cross-site, to a body application' => [static fn (): Request => self::cookie(self::TOKEN, null, null), Transport::BODY];
        yield 'an empty cookie, to a body application' => [static fn (): Request => self::cookie('', 'http://localhost', 'XMLHttpRequest'), Transport::BODY];
        yield 'the body, to a cookie application' => [static fn (): Request => self::json(['refresh_token' => self::TOKEN]), Transport::COOKIE];
        yield 'a header, to a cookie application' => [static fn (): Request => self::withHeaders(['X-Refresh-Token' => self::TOKEN]), Transport::COOKIE];
        yield 'an empty body field, to a cookie application' => [static fn (): Request => self::json(['refresh_token' => '']), Transport::COOKIE];
    }

    /**
     * A token carried only by another transport is a mismatch, before its value
     * is read.
     *
     * @param  \Closure(): \Illuminate\Http\Request  $request
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\Transport  $transport
     * @return void
     */
    #[DataProvider('provideMismatches')]
    public function testATokenByAnotherTransportIsAMismatch(\Closure $request, Transport $transport): void
    {
        self::assertSame(FailureReason::REFRESH_TRANSPORT_MISMATCH, self::transport($transport)->extract($request()));
        self::assertSame(FailureReason::REFRESH_TRANSPORT_MISMATCH, self::transport($transport)->extract($request()));
    }

    /**
     * Rows of `[the request's Cookie headers]` that carry the refresh cookie
     * twice.
     *
     * @return iterable<string, array{0: list<string>}>
     */
    public static function provideCookiesSentTwice(): iterable
    {
        $own = self::COOKIE . '=' . self::TOKEN;

        yield 'the name twice' => [['__Secure-refresh_token=planted; ' . $own]];
        yield 'the name twice without a space' => [['__Secure-refresh_token=planted;' . $own]];
        yield 'the name twice among others' => [['theme=dark; __Secure-refresh_token=planted; locale=en; ' . $own]];
        yield 'the name in two headers' => [['__Secure-refresh_token=planted', $own]];
        yield 'the name in two headers joined by a comma' => [['__Secure-refresh_token=planted, ' . $own]];
        yield 'a name with a dot' => [['__Secure-refresh.token=planted; ' . $own]];
        yield 'a name with a space' => [['__Secure-refresh token=planted; ' . $own]];
        yield 'a name with an index' => [['__Secure-refresh_token[x]=planted; ' . $own]];
        yield 'a name with an unclosed bracket' => [['__Secure-refresh[token=planted; ' . $own]];
        yield 'the name without a value' => [['__Secure-refresh_token; ' . $own]];
    }

    /**
     * A request that carries the refresh cookie twice is a conflict, whatever
     * the transport.
     *
     * @param  list<string>  $headers
     * @return void
     */
    #[DataProvider('provideCookiesSentTwice')]
    public function testACookieSentTwiceIsAConflict(array $headers): void
    {
        $request = self::cookie('planted', 'http://localhost', 'XMLHttpRequest');
        $request->headers->set('Cookie', $headers);

        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, self::transport(Transport::COOKIE)->extract($request));
        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, self::transport(Transport::COOKIE)->extract(self::crossSite($request)));
        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, self::transport()->extract($request));
        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, self::transport(Transport::COOKIE)->extract($request));
        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, self::transport(Transport::COOKIE)->extract(self::crossSite($request)));
        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, self::transport()->extract($request));
    }

    /**
     * Rows of `[the request's Cookie header]` that carry the refresh cookie
     * once.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideCookiesSentOnce(): iterable
    {
        $own = self::COOKIE . '=' . self::TOKEN;

        yield 'the name alone' => [$own];
        yield 'the name with others' => ['theme=dark; ' . $own . '; locale=en'];
        yield 'a name in another case' => ['__secure-refresh_token=planted; ' . $own];
        yield 'a name with a prefix' => ['x__Secure-refresh_token=planted; ' . $own];
        yield 'a name with a suffix' => ['__Secure-refresh_token2=planted; ' . $own];
        yield 'the name as a value' => ['theme=__Secure-refresh_token; ' . $own];
        yield 'the name with an unclosed bracket after it' => ['__Secure-refresh_token[=planted; ' . $own];
        yield 'a name cut at an index before the end' => ['__Secure-refresh[token]=planted; ' . $own];
    }

    /**
     * A request that carries the refresh cookie once presents it to a cookie
     * application.
     *
     * @param  string  $header
     * @return void
     */
    #[DataProvider('provideCookiesSentOnce')]
    public function testACookieSentOnceIsPresented(string $header): void
    {
        $request = self::cookie(self::TOKEN, 'http://localhost', 'XMLHttpRequest');
        $request->headers->set('Cookie', $header);

        self::assertSame(self::TOKEN, self::presented(self::transport(Transport::COOKIE)->extract($request))->token->reveal());
        self::assertSame([RefreshTokenSource::COOKIE], self::presented(self::transport(Transport::COOKIE)->extract($request))->carriers);
    }

    /**
     * Rows of `[the request, the transport]` that carry no single non-empty
     * string.
     *
     * @return iterable<string, array{0: \Closure(): \Illuminate\Http\Request, 1: \SineMacula\Laravel\Authentication\Http\Enums\Transport}>
     */
    public static function provideInvalidValues(): iterable
    {
        yield 'an empty body field' => [static fn (): Request => self::json(['refresh_token' => '']), Transport::BODY];
        yield 'a null body field' => [static fn (): Request => self::json(['refresh_token' => null]), Transport::BODY];
        yield 'an array body field' => [static fn (): Request => self::json(['refresh_token' => [self::TOKEN]]), Transport::BODY];
        yield 'a number body field' => [static fn (): Request => self::json(['refresh_token' => 42]), Transport::BODY];
        yield 'an empty header' => [static fn (): Request => self::withHeaders(['X-Refresh-Token' => '']), Transport::BODY];
        yield 'a header sent twice' => [static function (): Request {
            $request = Request::create('/auth/refresh', 'POST');
            $request->headers->set('X-Refresh-Token', [self::TOKEN, self::TOKEN]);

            return $request;
        }, Transport::BODY];
        yield 'an empty cookie' => [static fn (): Request => self::cookie('', 'http://localhost', 'XMLHttpRequest'), Transport::COOKIE];
        yield 'a cookie that could not be decrypted' => [static fn (): Request => self::cookie(null, 'http://localhost', 'XMLHttpRequest'), Transport::COOKIE];
        yield 'an array cookie' => [static fn (): Request => self::cookie([self::TOKEN], 'http://localhost', 'XMLHttpRequest'), Transport::COOKIE];
    }

    /**
     * A value that is not one non-empty string is an invalid token.
     *
     * @param  \Closure(): \Illuminate\Http\Request  $request
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\Transport  $transport
     * @return void
     */
    #[DataProvider('provideInvalidValues')]
    public function testAValueThatIsNotOneNonEmptyStringIsInvalid(\Closure $request, Transport $transport): void
    {
        self::assertSame(FailureReason::TOKEN_INVALID, self::transport($transport)->extract($request()));
        self::assertSame(FailureReason::TOKEN_INVALID, self::transport($transport)->extract($request()));
    }

    /**
     * Rows of `[the Origin header, the custom header]` a cookie refresh is
     * refused for.
     *
     * @return iterable<string, array{0: ?string, 1: ?string}>
     */
    public static function provideCrossSiteRequests(): iterable
    {
        yield 'no origin' => [null, 'XMLHttpRequest'];
        yield 'another origin' => ['https://evil.example.test', 'XMLHttpRequest'];
        yield 'an opaque origin' => ['null', 'XMLHttpRequest'];
        yield 'the own origin on another scheme' => ['https://localhost', 'XMLHttpRequest'];
        yield 'no custom header' => ['http://localhost', null];
        yield 'an empty custom header' => [self::ALLOWED_ORIGIN, ''];
    }

    /**
     * The extraction leaves the same-site judgement out; judging the token then
     * refuses it.
     *
     * @param  ?string  $origin
     * @param  ?string  $csrf
     * @return void
     */
    #[DataProvider('provideCrossSiteRequests')]
    public function testTheExtractionLeavesTheSameSiteJudgementOut(?string $origin, ?string $csrf): void
    {
        $transport = self::transport(Transport::COOKIE);
        $request   = self::cookie(self::TOKEN, $origin, $csrf);
        $extracted = self::presented($transport->extract($request));

        self::assertSame(self::TOKEN, $extracted->token->reveal());
        self::assertSame(RefreshTokenSource::COOKIE, $extracted->source);
        self::assertSame(FailureReason::TOKEN_INVALID, $transport->extract(self::cookie('', $origin, $csrf)));
        self::assertSame(FailureReason::CROSS_SITE_REQUEST, $transport->judge($extracted, ClientContext::fromRequest($request)));
    }

    /**
     * Only a request from the own site or an allowed origin, with the custom
     * header, is same-site.
     *
     * @param  ?string  $origin
     * @param  ?string  $csrf
     * @return void
     */
    #[DataProvider('provideCrossSiteRequests')]
    public function testOnlyARequestFromTheOwnSiteWithTheHeaderIsSameSite(?string $origin, ?string $csrf): void
    {
        $transport = self::transport(Transport::COOKIE);

        self::assertFalse($transport->isSameSiteRequest(self::cookie(null, $origin, $csrf)));
        self::assertFalse($transport->isSameSiteRequest(self::signIn($origin, $csrf)));
        self::assertTrue($transport->isSameSiteRequest(self::signIn('http://localhost', 'fetch')));
        self::assertTrue($transport->isSameSiteRequest(self::signIn(self::ALLOWED_ORIGIN, 'fetch')));
    }

    /**
     * Rows of `[client context, whether it is same-site]`, each fact failing
     * alone.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Http\ClientContext, 1: bool}>
     */
    public static function provideClients(): iterable
    {
        $own    = 'http://localhost';
        $header = ['x-requested-with'];

        yield 'the own origin with the header' => [new ClientContext(null, null, $own, $own, $header), true];
        yield 'an allowed origin with the header' => [new ClientContext(null, null, self::ALLOWED_ORIGIN, $own, $header), true];
        yield 'an allowed origin with no scheme and host' => [new ClientContext(null, null, self::ALLOWED_ORIGIN, null, $header), true];
        yield 'the header spelt in another case' => [new ClientContext(null, null, $own, $own, ['X-Requested-With']), true];
        yield 'an unapproved origin with the header' => [new ClientContext(null, null, 'https://evil.example.test', $own, $header), false];
        yield 'the own origin without the header' => [new ClientContext(null, null, $own, $own, ['origin']), false];
        yield 'an allowed origin without the header' => [new ClientContext(null, null, self::ALLOWED_ORIGIN, $own, []), false];
        yield 'the header with no origin' => [new ClientContext(null, null, null, $own, $header), false];
        yield 'the header with neither origin nor scheme and host' => [new ClientContext(null, null, null, null, $header), false];
        yield 'the header with an origin and no scheme and host' => [new ClientContext(null, null, $own, null, $header), false];
        yield 'nothing but the plain values' => [new ClientContext('203.0.113.7', 'Browser/1.0'), false];
    }

    /**
     * A client is same-site only with the custom header and its own or an
     * allowed origin.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  bool  $sameSite
     * @return void
     */
    #[DataProvider('provideClients')]
    public function testOnlyAClientFromTheOwnSiteWithTheHeaderIsSameSite(ClientContext $client, bool $sameSite): void
    {
        self::assertSame($sameSite, self::transport(Transport::COOKIE)->isSameSiteClient($client));
    }

    /**
     * The configured header is matched as the header bag files names.
     *
     * @return void
     */
    public function testTheConfiguredHeaderIsJudgedAsTheHeaderBagFilesIt(): void
    {
        $spelt   = new RefreshTokenTransport(new RefreshTokenSettings(Transport::COOKIE, 'token', null, 'refresh', '/auth', [], 'x_CSRF_token'));
        $request = Request::create('/auth/sign-in', 'POST', server: ['HTTP_ORIGIN' => 'http://localhost', 'HTTP_X_CSRF_TOKEN' => '1']);

        self::assertTrue($spelt->isSameSiteClient(ClientContext::fromRequest($request)));
        self::assertTrue($spelt->isSameSiteRequest($request));
        self::assertFalse(self::transport(Transport::COOKIE)->isSameSiteRequest($request));
    }

    /**
     * The request's check and the client's agree on the same request.
     *
     * @param  ?string  $origin
     * @param  ?string  $csrf
     * @return void
     */
    #[DataProvider('provideCrossSiteRequests')]
    public function testTheRequestsCheckIsTheClientsCheck(?string $origin, ?string $csrf): void
    {
        $transport = self::transport(Transport::COOKIE);

        foreach ([self::signIn($origin, $csrf), self::signIn('http://localhost', 'fetch'), self::signIn(self::ALLOWED_ORIGIN, 'fetch')] as $request) {
            self::assertSame($transport->isSameSiteClient(ClientContext::fromRequest($request)), $transport->isSameSiteRequest($request));
        }
    }

    /**
     * The check and a cookie's extraction leave conflicting forwarded addresses
     * unread.
     *
     * @return void
     */
    public function testConflictingForwardedAddressesAreLeftToTheApplication(): void
    {
        Request::setTrustedProxies(['10.0.0.1'], Request::HEADER_FORWARDED | Request::HEADER_X_FORWARDED_FOR);

        $request = self::cookie(self::TOKEN, 'http://localhost', 'fetch');

        $request->server->set('REMOTE_ADDR', '10.0.0.1');
        $request->headers->set('Forwarded', 'for=198.51.100.1');
        $request->headers->set('X-Forwarded-For', '198.51.100.2');

        $transport = self::transport(Transport::COOKIE);

        self::assertTrue($transport->isSameSiteRequest($request));
        self::assertTrue($transport->isSameSiteRequest($request));
        self::assertSame(self::TOKEN, self::presented($transport->extract($request))->token->reveal());

        $this->expectException(ConflictingHeadersException::class);

        $request->ip();
    }

    /**
     * A request whose host Symfony refuses is not same-site, and checking it
     * throws nothing.
     *
     * @return void
     */
    public function testARequestWithARefusedHostIsNotSameSite(): void
    {
        $request = self::signIn('http://bad!host', 'fetch');

        $request->headers->set('Host', 'bad!host');

        self::assertFalse(self::transport(Transport::COOKIE)->isSameSiteRequest($request));
    }

    /**
     * The application's own body field, header and cookie names are read.
     *
     * @return void
     */
    public function testTheConfiguredNamesAreRead(): void
    {
        $body   = new RefreshTokenTransport(new RefreshTokenSettings(Transport::BODY, 'token', 'X-Token', 'refresh', null, [], 'X-CSRF'));
        $cookie = new RefreshTokenTransport(new RefreshTokenSettings(Transport::COOKIE, 'token', 'X-Token', 'refresh', '/auth', [], 'X-CSRF'));
        $sent   = Request::create('/auth/refresh', 'POST', [], ['refresh' => self::TOKEN], [], ['HTTP_ORIGIN' => 'http://localhost', 'HTTP_X_CSRF' => '1']);

        self::assertSame(RefreshTokenSource::BODY, self::presented($body->extract(self::json(['token' => self::TOKEN])))->source);
        self::assertSame(RefreshTokenSource::HEADER, self::presented($body->extract(self::withHeaders(['X-Token' => self::TOKEN])))->source);
        self::assertSame(RefreshTokenSource::COOKIE, self::presented($cookie->extract($sent))->source);
        self::assertSame(FailureReason::REFRESH_TRANSPORT_MISMATCH, $body->extract($sent));
        self::assertNull($body->extract(self::json(['refresh_token' => self::TOKEN])));
        self::assertNull($cookie->extract(self::cookie(self::TOKEN, 'http://localhost', 'XMLHttpRequest')));
    }

    /**
     * Extracting changes nothing on the request.
     *
     * @return void
     */
    public function testExtractingHasNoSideEffects(): void
    {
        $request = self::cookie(self::TOKEN, 'http://localhost', 'XMLHttpRequest');
        $before  = [$request->cookies->all(), $request->headers->all(), $request->request->all()];

        self::transport(Transport::COOKIE)->extract($request);

        self::assertSame($before, [$request->cookies->all(), $request->headers->all(), $request->request->all()]);
    }

    /**
     * The transport of a guard is built from the configuration.
     *
     * @return void
     */
    public function testTheTransportOfAGuardIsBuiltFromTheConfiguration(): void
    {
        $config = new ConfigRepository([
            'auth' => ['guards' => [
                'api'     => ['driver' => 'jwt', 'refresh_token' => ['header' => 'X-Token']],
                'browser' => ['driver' => 'jwt', 'refresh_token' => ['transport' => 'cookie', 'cookie' => ['path' => '/auth']]],
            ]],
            'authentication' => ['refresh_token' => ['transport' => 'body', 'body_field' => 'refresh_token', 'header' => 'X-Refresh-Token', 'cookie' => [
                'name' => null, 'path' => null, 'allowed_origins' => [], 'csrf_header' => 'X-Requested-With',
            ]]],
        ]);

        $transport = RefreshTokenTransport::forGuard('api', $config);

        self::assertFalse($transport->usesCookie());
        self::assertTrue(RefreshTokenTransport::forGuard('browser', $config)->usesCookie());
        self::assertSame(RefreshTokenSource::HEADER, self::presented($transport->extract(self::withHeaders(['X-Token' => self::TOKEN])))->source);
        self::assertNull($transport->extract(self::withHeaders(['X-Refresh-Token' => self::TOKEN])));
    }

    /**
     * Rows of `[seconds to the idle deadline, seconds to the absolute one or
     * null]`.
     *
     * @return iterable<string, array{0: int, 1: ?int}>
     */
    public static function provideDeadlines(): iterable
    {
        yield 'the idle deadline first' => [3600, 7200];
        yield 'the absolute deadline first' => [7200, 3600];
        yield 'no absolute deadline' => [3600, null];
    }

    /**
     * A cookie application's refresh token moves into a cookie that expires
     * with the session.
     *
     * @param  int  $idle
     * @param  ?int  $absolute
     * @return void
     */
    #[DataProvider('provideDeadlines')]
    public function testACookieApplicationsPairCarriesTheCookieUntilTheSessionEnds(int $idle, ?int $absolute): void
    {
        $now     = CarbonImmutable::createStrict(2026, 4, 6, 12, 0, 0);
        $access  = new Secret('access-token');
        $expires = $now->addSeconds(240);

        Carbon::setTestNow($now);

        try {
            $session   = new PlainSessionFixture('session-1', $now->addSeconds($idle), $absolute === null ? null : $now->addSeconds($absolute));
            $delivered = self::transport(Transport::COOKIE)->deliver(new TokenPair($access, $expires, 240, new Secret(self::TOKEN)), $session);
        } finally {
            Carbon::setTestNow();
        }

        self::assertSame($access, $delivered->accessToken);
        self::assertSame($expires, $delivered->expiresAt);
        self::assertSame(240, $delivered->expiresIn);
        self::assertNull($delivered->refreshToken);
        self::assertNotNull($delivered->refreshCookie);
        self::assertSame(
            [self::COOKIE, '/auth', $now->getTimestamp() + 3600],
            [$delivered->refreshCookie->name, $delivered->refreshCookie->path, $delivered->refreshCookie->expiresAt->getTimestamp()],
        );

        $cookie = $delivered->refreshCookie->cookie();

        self::assertSame(self::COOKIE, $cookie->getName());
        self::assertSame(self::TOKEN, $cookie->getValue());
        self::assertSame('/auth', $cookie->getPath());
        self::assertNull($cookie->getDomain());
        self::assertSame($now->getTimestamp() + 3600, $cookie->getExpiresTime());
        self::assertTrue($cookie->isHttpOnly());
        self::assertTrue($cookie->isSecure());
        self::assertSame(Cookie::SAMESITE_STRICT, $cookie->getSameSite());
        self::assertFalse($cookie->isRaw());
    }

    /**
     * A body application's pair, and a pair already delivered, are kept as they
     * are.
     *
     * @return void
     */
    public function testABodyApplicationsPairAndADeliveredOneAreKept(): void
    {
        $session = new PlainSessionFixture('session-1', Carbon::now()->addHour());
        $pair    = new TokenPair(new Secret('access-token'), CarbonImmutable::now()->addMinutes(5), 300, new Secret(self::TOKEN));

        self::assertSame($pair, self::transport()->deliver($pair, $session));

        $delivered = self::transport(Transport::COOKIE)->deliver($pair, $session);

        self::assertSame($delivered, self::transport(Transport::COOKIE)->deliver($delivered, $session));
    }

    /**
     * A session that has ended, or has no idle deadline, is delivered no
     * cookie.
     *
     * @return void
     */
    public function testAnEndedSessionGetsNoCookie(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot set a refresh cookie for a session that has ended or that has no idle deadline.');

        $pair = new TokenPair(new Secret('access-token'), CarbonImmutable::now()->addMinutes(5), 300, new Secret(self::TOKEN));

        self::transport(Transport::COOKIE)->deliver($pair, new PlainSessionFixture('session-1'));
    }

    /**
     * The clearing cookie matches the cookie it clears and has already expired.
     *
     * @return void
     */
    public function testTheClearingCookieMatchesTheCookieAndHasExpired(): void
    {
        $cookie = self::transport(Transport::COOKIE)->forgetCookie();

        self::assertSame(self::COOKIE, $cookie->getName());
        self::assertNull($cookie->getValue());
        self::assertSame('/auth', $cookie->getPath());
        self::assertNull($cookie->getDomain());
        self::assertTrue($cookie->isCleared());
        self::assertLessThan(time(), $cookie->getExpiresTime());
        self::assertTrue($cookie->isHttpOnly());
        self::assertTrue($cookie->isSecure());
        self::assertFalse($cookie->isRaw());
        self::assertSame(Cookie::SAMESITE_STRICT, $cookie->getSameSite());
    }

    /**
     * A body application has no cookie to clear, even with a path configured.
     *
     * @return void
     */
    public function testABodyApplicationClearsNoCookie(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('This application\'s refresh token travels in the body: set its `refresh_token.transport` to `cookie`');

        self::transport()->forgetCookie();
    }

    /**
     * A body application whose guard name makes no cookie name looks for no
     * cookie.
     *
     * @return void
     */
    public function testABodyApplicationWithoutACookieNameLooksForNoCookie(): void
    {
        $transport = new RefreshTokenTransport(new RefreshTokenSettings(Transport::BODY, 'refresh_token', 'X-Refresh-Token', null, null, [], 'X-Requested-With'));

        $fromBody   = self::presented($transport->extract(self::cookie('another-value', 'http://localhost', 'XMLHttpRequest', ['refresh_token' => self::TOKEN])));
        $fromHeader = self::presented($transport->extract(self::withHeaders(['X-Refresh-Token' => self::TOKEN])));

        self::assertSame(RefreshTokenSource::BODY, $fromBody->source);
        self::assertSame(self::TOKEN, $fromBody->token->reveal());
        self::assertSame(RefreshTokenSource::HEADER, $fromHeader->source);
        self::assertNull($transport->extract(self::cookie(self::TOKEN, 'http://localhost', 'XMLHttpRequest')));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('This application\'s refresh token travels in the body: set its `refresh_token.transport` to `cookie`');

        $transport->forgetCookie();
    }

    /**
     * Rows of `[the transport, the source, the carriers]` whose carriers are
     * not the source alone.
     *
     * @formatter:off
     *
     * @phpcs:disable Generic.Files.LineLength.TooLong
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Http\Enums\Transport, 1: \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource, 2: array<int, \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource>}>
     *
     * @phpcs:enable Generic.Files.LineLength.TooLong
     *
     * @formatter:on
     */
    public static function provideConflictingCarriers(): iterable
    {
        yield 'the body and a header' => [Transport::BODY, RefreshTokenSource::BODY, [RefreshTokenSource::BODY, RefreshTokenSource::HEADER]];
        yield 'a header and the body' => [Transport::BODY, RefreshTokenSource::HEADER, [RefreshTokenSource::HEADER, RefreshTokenSource::BODY]];
        yield 'the cookie twice' => [Transport::COOKIE, RefreshTokenSource::COOKIE, [RefreshTokenSource::COOKIE, RefreshTokenSource::COOKIE]];
        yield 'the cookie and the body' => [Transport::COOKIE, RefreshTokenSource::COOKIE, [RefreshTokenSource::COOKIE, RefreshTokenSource::BODY]];
        yield 'no carrier' => [Transport::COOKIE, RefreshTokenSource::COOKIE, []];
        yield 'a carrier that is not the source' => [Transport::COOKIE, RefreshTokenSource::COOKIE, [RefreshTokenSource::BODY]];
        yield 'the source under another key' => [Transport::BODY, RefreshTokenSource::BODY, [1 => RefreshTokenSource::BODY]];
        yield 'the cookie and the body, to a body application' => [Transport::BODY, RefreshTokenSource::COOKIE, [RefreshTokenSource::COOKIE, RefreshTokenSource::BODY]];
    }

    /**
     * A presented token whose carriers are not its source alone is a conflict.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\Transport  $transport
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @param  array<int, \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource>  $carriers
     * @return void
     */
    #[DataProvider('provideConflictingCarriers')]
    public function testCarriersThatAreNotTheSourceAloneAreAConflict(Transport $transport, RefreshTokenSource $source, array $carriers): void
    {
        $presented = new PresentedRefreshToken(new Secret(self::TOKEN), $source, $carriers); // @phpstan-ignore argument.type (a list with another key is what is judged)

        self::assertSame(FailureReason::REFRESH_TOKEN_CONFLICT, self::transport($transport)->judge($presented, self::sameSiteClient()));
    }

    /**
     * Rows of `[the transport, the configured header, the source]` the
     * application does not read.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Authentication\Http\Enums\Transport, 1: ?string, 2: \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource}>
     */
    public static function provideMismatchedSources(): iterable
    {
        yield 'the cookie, to a body application' => [Transport::BODY, 'X-Refresh-Token', RefreshTokenSource::COOKIE];
        yield 'the body, to a cookie application' => [Transport::COOKIE, 'X-Refresh-Token', RefreshTokenSource::BODY];
        yield 'a header, to a cookie application' => [Transport::COOKIE, 'X-Refresh-Token', RefreshTokenSource::HEADER];
        yield 'a header, to a cookie application without one' => [Transport::COOKIE, null, RefreshTokenSource::HEADER];
        yield 'a header, to a body application without one' => [Transport::BODY, null, RefreshTokenSource::HEADER];
    }

    /**
     * A presented token whose source the transport does not read is a mismatch.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\Transport  $transport
     * @param  ?string  $header
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @return void
     */
    #[DataProvider('provideMismatchedSources')]
    public function testASourceThatIsNotTheApplicationsCarrierIsAMismatch(Transport $transport, ?string $header, RefreshTokenSource $source): void
    {
        $presented = new PresentedRefreshToken(new Secret(self::TOKEN), $source, [$source]);

        self::assertSame(FailureReason::REFRESH_TRANSPORT_MISMATCH, self::transport($transport, $header)->judge($presented, self::sameSiteClient()));
    }

    /**
     * A token presented in the cookie is judged by the client's same-site
     * facts.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  bool  $sameSite
     * @return void
     */
    #[DataProvider('provideClients')]
    public function testACookieTokenIsJudgedByTheClientsSameSiteFacts(ClientContext $client, bool $sameSite): void
    {
        $presented = new PresentedRefreshToken(new Secret(self::TOKEN), RefreshTokenSource::COOKIE, [RefreshTokenSource::COOKIE]);

        self::assertSame($sameSite ? null : FailureReason::CROSS_SITE_REQUEST, self::transport(Transport::COOKIE)->judge($presented, $client));
    }

    /**
     * A token from a body application's body field or header is never judged
     * same-site.
     *
     * @return void
     */
    public function testABodyApplicationsTokenIsNotJudgedSameSite(): void
    {
        $transport = self::transport();
        $client    = new ClientContext(null, null);

        self::assertNull($transport->judge(new PresentedRefreshToken(new Secret(self::TOKEN), RefreshTokenSource::BODY, [RefreshTokenSource::BODY]), $client));
        self::assertNull($transport->judge(new PresentedRefreshToken(new Secret(self::TOKEN), RefreshTokenSource::HEADER, [RefreshTokenSource::HEADER]), $client));
    }

    /**
     * A transport of the given kind with the cookie scoped to `/auth` and one
     * allowed origin.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\Transport  $transport
     * @param  ?string  $header
     * @return \SineMacula\Laravel\Authentication\Http\RefreshTokenTransport
     */
    private static function transport(Transport $transport = Transport::BODY, ?string $header = 'X-Refresh-Token'): RefreshTokenTransport
    {
        return new RefreshTokenTransport(new RefreshTokenSettings($transport, 'refresh_token', $header, self::COOKIE, '/auth', [self::ALLOWED_ORIGIN], 'X-Requested-With'));
    }

    /**
     * A client from the API's own origin with the custom header.
     *
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    private static function sameSiteClient(): ClientContext
    {
        return new ClientContext('203.0.113.7', 'Browser/1.0', 'http://localhost', 'http://localhost', ['x-requested-with']);
    }

    /**
     * A JSON refresh request with the body and headers.
     *
     * @param  array<string, mixed>  $body
     * @param  array<string, string>  $headers
     * @return \Illuminate\Http\Request
     *
     * @throws \JsonException
     */
    private static function json(array $body, array $headers = []): Request
    {
        $request = Request::create('/auth/refresh', 'POST', [], [], [], ['CONTENT_TYPE' => 'application/json'], json_encode($body, JSON_THROW_ON_ERROR));
        $request->headers->add($headers);

        return $request;
    }

    /**
     * A refresh request with no body and the headers.
     *
     * @param  array<string, string>  $headers
     * @return \Illuminate\Http\Request
     */
    private static function withHeaders(array $headers): Request
    {
        $request = Request::create('/auth/refresh', 'POST');
        $request->headers->add($headers);

        return $request;
    }

    /**
     * A refresh request carrying the cookie from the origin with the custom
     * header.
     *
     * @param  mixed  $value
     * @param  ?string  $origin
     * @param  ?string  $csrf
     * @param  array<string, mixed>  $body
     * @return \Illuminate\Http\Request
     */
    private static function cookie(mixed $value, ?string $origin, ?string $csrf, array $body = []): Request
    {
        $server = array_filter(['HTTP_ORIGIN' => $origin, 'HTTP_X_REQUESTED_WITH' => $csrf], static fn (?string $header): bool => $header !== null);

        return Request::create('/auth/refresh', 'POST', $body, [self::COOKIE => $value], [], $server);
    }

    /**
     * The request with its `Origin` and custom header removed.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Request
     */
    private static function crossSite(Request $request): Request
    {
        $request = clone $request;
        $request->headers->remove('Origin');
        $request->headers->remove('X-Requested-With');

        return $request;
    }

    /**
     * A sign-in request carrying no token, from the origin with the custom
     * header.
     *
     * @param  ?string  $origin
     * @param  ?string  $csrf
     * @return \Illuminate\Http\Request
     */
    private static function signIn(?string $origin, ?string $csrf): Request
    {
        $server = array_filter(['HTTP_ORIGIN' => $origin, 'HTTP_X_REQUESTED_WITH' => $csrf], static fn (?string $header): bool => $header !== null);

        return Request::create('/auth/sign-in', 'POST', server: $server);
    }

    /**
     * A request of the method whose parsed form body holds the token.
     *
     * @param  string  $method
     * @return \Illuminate\Http\Request
     */
    private static function formBody(string $method): Request
    {
        $request = Request::create('/auth/refresh', $method);
        $request->request->set('refresh_token', self::TOKEN);

        return $request;
    }

    /**
     * Narrow an extraction to the token it presented.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Http\PresentedRefreshToken|null  $read
     * @return \SineMacula\Laravel\Authentication\Http\PresentedRefreshToken
     */
    private static function presented(FailureReason|PresentedRefreshToken|null $read): PresentedRefreshToken
    {
        self::assertInstanceOf(PresentedRefreshToken::class, $read);

        return $read;
    }
}
