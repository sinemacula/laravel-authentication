<?php

declare(strict_types = 1);

namespace Tests\Feature\Http;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use Illuminate\Routing\UrlGenerator;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Authentication\Http\SignedLink;
use Tests\TestCase;

/**
 * Feature tests for a signed link held as plain values: it captures the address
 * a request arrived at, behind the application's trusted proxies, and the raw
 * query string as received, and the request it rebuilds from them alone passes
 * the framework's signature check exactly when the link was signed so: a query
 * changed on the way fails, an expired link is still authentic but expired, and
 * a link signed with a key since rotated passes while that key is a previous
 * key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignedLink::class)]
final class SignedLinkTest extends TestCase
{
    /**
     * Register the route the links are signed for.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        Route::get('/links/{id}', static fn (): string => 'ok')->name('links.show');
    }

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
     * A link captured from the request to it holds the address without its
     * query and the raw query string, and the request rebuilt from them passes
     * the signature and expiry checks.
     *
     * @return void
     */
    public function testALinkCapturedFromItsRequestIsAuthentic(): void
    {
        $signed = $this->urls()->temporarySignedRoute('links.show', CarbonImmutable::now()->addHour(), ['id' => 7, 'note' => 'a b/c']);
        $link   = SignedLink::fromRequest(Request::create($signed));

        self::assertSame('http://localhost/links/7', $link->url);
        self::assertSame((string) parse_url($signed, PHP_URL_QUERY), $link->query);

        $request = $link->toRequest();

        self::assertTrue($this->urls()->hasCorrectSignature($request));
        self::assertTrue($this->urls()->signatureHasNotExpired($request));
        self::assertSame('a b/c', $request->query('note'));
    }

    /**
     * Behind a trusted proxy the link is captured at the address the client
     * used, which it was signed for, not the one the proxy forwarded to.
     *
     * @return void
     */
    public function testALinkBehindAProxyIsCapturedAtItsPublicAddress(): void
    {
        Request::setTrustedProxies(['10.0.0.1'], Request::HEADER_X_FORWARDED_PROTO | Request::HEADER_X_FORWARDED_HOST | Request::HEADER_X_FORWARDED_PORT);

        $served = $this->urls()->getRequest();

        $this->urls()->setRequest(Request::create('https://accounts.example.test/'));

        $signed = $this->urls()->signedRoute('links.show', ['id' => 7]);

        $this->urls()->setRequest($served);

        self::assertStringStartsWith('https://accounts.example.test/links/7?', $signed);

        $request = Request::create('http://internal:8080/links/7?' . parse_url($signed, PHP_URL_QUERY), server: [
            'REMOTE_ADDR'            => '10.0.0.1',
            'HTTP_X_FORWARDED_PROTO' => 'https',
            'HTTP_X_FORWARDED_HOST'  => 'accounts.example.test',
            'HTTP_X_FORWARDED_PORT'  => '443',
        ]);

        $link = SignedLink::fromRequest($request);

        self::assertSame('https://accounts.example.test/links/7', $link->url);
        self::assertTrue($this->urls()->hasCorrectSignature($link->toRequest()));
    }

    /**
     * The raw query string is checked as it was sent: a link whose query
     * encodes its fields otherwise than the framework would re-encode them
     * stays authentic, and one whose query was changed on the way does not.
     *
     * @return void
     */
    public function testTheQueryIsCheckedAsItWasSent(): void
    {
        $query   = 'note=a%20b&id=7';
        $address = 'http://localhost/links/7';
        $key     = Config::string('app.key');
        $signed  = $query . '&signature=' . hash_hmac('sha256', "{$address}?{$query}", $key);

        self::assertTrue($this->urls()->hasCorrectSignature((new SignedLink($address, $signed))->toRequest()));

        foreach ([str_replace('a%20b', 'a+b', $signed), str_replace('id=7', 'id=8', $signed), $signed . '&extra=1'] as $tampered) {
            self::assertFalse($this->urls()->hasCorrectSignature((new SignedLink($address, $tampered))->toRequest()), $tampered);
        }

        self::assertFalse($this->urls()->hasCorrectSignature((new SignedLink('http://localhost/links/8', $signed))->toRequest()));
    }

    /**
     * An expired link is still authentic, and its expiry has passed.
     *
     * @return void
     */
    public function testAnExpiredLinkIsAuthenticButExpired(): void
    {
        $signed = $this->urls()->temporarySignedRoute('links.show', CarbonImmutable::now()->addMinute(), ['id' => 7]);

        $this->travel(2)->minutes();

        $request = SignedLink::fromRequest(Request::create($signed))->toRequest();

        self::assertTrue($this->urls()->hasCorrectSignature($request));
        self::assertFalse($this->urls()->signatureHasNotExpired($request));
    }

    /**
     * A link signed with a key since rotated passes while that key is one of
     * the previous keys, and fails once it is not.
     *
     * @return void
     */
    public function testALinkSignedWithARotatedKeyPassesWhileTheKeyIsAPreviousOne(): void
    {
        $old    = Config::string('app.key');
        $signed = $this->urls()->signedRoute('links.show', ['id' => 7]);

        config()->set('app.key', 'base64:' . base64_encode(str_repeat('n', 32)));
        config()->set('app.previous_keys', [$old]);

        self::assertTrue($this->urls()->hasCorrectSignature(SignedLink::fromRequest(Request::create($signed))->toRequest()));

        config()->set('app.previous_keys', []);

        self::assertFalse($this->urls()->hasCorrectSignature(SignedLink::fromRequest(Request::create($signed))->toRequest()));
    }

    /**
     * A request without a query string is captured with an empty one.
     *
     * @return void
     */
    public function testARequestWithoutAQueryIsCapturedWithAnEmptyOne(): void
    {
        $link = SignedLink::fromRequest(Request::create('http://localhost/links/7/'));

        self::assertSame(['http://localhost/links/7', ''], [$link->url, $link->query]);
        self::assertFalse($this->urls()->hasCorrectSignature($link->toRequest()));
    }

    /**
     * The application's URL generator.
     *
     * @return \Illuminate\Routing\UrlGenerator
     */
    private function urls(): UrlGenerator
    {
        $urls = app('url');

        self::assertInstanceOf(UrlGenerator::class, $urls);

        return $urls;
    }
}
