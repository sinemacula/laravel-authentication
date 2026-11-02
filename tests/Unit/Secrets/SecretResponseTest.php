<?php

declare(strict_types = 1);

namespace Tests\Unit\Secrets;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Response;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;
use Symfony\Component\HttpFoundation\Response as SymfonyResponse;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * Unit tests for the responses that carry a secret: the body reveals every
 * secret in it, and no response is marked to be stored.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SecretResponse::class)]
final class SecretResponseTest extends TestCase
{
    /**
     * Every secret in the data, at any depth of arrays, is revealed into the
     * body, and every other value is kept as it is, keys and order included;
     * given no status, the response is `200 OK`.
     *
     * @return void
     */
    public function testTheBodyRevealsEverySecretAtAnyDepth(): void
    {
        $response = SecretResponse::json([
            'access_token'  => new Secret('access-plaintext'),
            'refresh_token' => null,
            'expires_in'    => 300,
            'pending'       => ['credential' => new Secret('pending-plaintext'), 'requires' => ['mfa']],
            'keys'          => [new Secret('key-one'), 'not-a-secret', [new Secret('key-two')]],
        ]);

        self::assertSame([
            'access_token'  => 'access-plaintext',
            'refresh_token' => null,
            'expires_in'    => 300,
            'pending'       => ['credential' => 'pending-plaintext', 'requires' => ['mfa']],
            'keys'          => ['key-one', 'not-a-secret', ['key-two']],
        ], $response->getData(true));
        self::assertSame(200, $response->getStatusCode());
    }

    /**
     * The response keeps the status and headers given, and is never stored:
     * `Cache-Control: no-store` and `Pragma: no-cache` replace any caching
     * headers given.
     *
     * @return void
     */
    public function testTheResponseKeepsItsStatusAndHeadersAndIsNeverStored(): void
    {
        $response = SecretResponse::json(['credential' => new Secret('pending-plaintext')], 202, [
            'X-Request-Id'  => 'request-1',
            'Cache-Control' => 'public, max-age=3600',
            'Pragma'        => 'cache',
        ]);

        self::assertInstanceOf(JsonResponse::class, $response);
        self::assertSame(202, $response->getStatusCode());
        self::assertSame('request-1', $response->headers->get('X-Request-Id'));
        self::assertNoStore($response);
    }

    /**
     * Any response is marked not to be stored, replacing whatever caching it
     * allowed, and is the same response back, of its own class.
     *
     * @return void
     */
    public function testWithoutStoringReplacesTheResponsesCaching(): void
    {
        $response = (new Response('body', 200))->setPublic()->setMaxAge(3600)->setSharedMaxAge(7200);
        $streamed = new StreamedResponse(static function (): void {}, 200, ['Cache-Control' => 'max-age=60']);

        self::assertSame($response, SecretResponse::withoutStoring($response));
        self::assertSame($streamed, SecretResponse::withoutStoring($streamed));
        self::assertNoStore($response);
        self::assertNoStore($streamed);
        self::assertSame('body', $response->getContent());
    }

    /**
     * Assert the response may not be stored, and allows no caching at all.
     *
     * @param  \Symfony\Component\HttpFoundation\Response  $response
     * @return void
     */
    private static function assertNoStore(SymfonyResponse $response): void
    {
        self::assertTrue($response->headers->hasCacheControlDirective('no-store'));
        self::assertFalse($response->headers->hasCacheControlDirective('public'));
        self::assertFalse($response->headers->hasCacheControlDirective('max-age'));
        self::assertFalse($response->headers->hasCacheControlDirective('s-maxage'));
        self::assertSame('no-cache', $response->headers->get('Pragma'));
    }
}
