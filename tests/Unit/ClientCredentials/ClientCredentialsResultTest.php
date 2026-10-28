<?php

declare(strict_types = 1);

namespace Tests\Unit\ClientCredentials;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsResult;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;

/**
 * Unit tests for the RFC 6749 shapes a client credentials exchange answers in:
 * the token response, every error with its status, and the headers.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ClientCredentialsResult::class)]
final class ClientCredentialsResultTest extends TestCase
{
    /**
     * A grant answers 200 with the token, its type, lifetime and scopes, never
     * cached, and no challenge or wait.
     *
     * @return void
     */
    public function testAGrantIsTheTokenResponse(): void
    {
        $result   = ClientCredentialsResult::granted('token-value', 300, ['read', 'write']);
        $response = $result->toResponse(Request::create('/'));

        self::assertTrue($result->isGranted());
        self::assertSame(['access_token' => 'token-value', 'token_type' => 'Bearer', 'expires_in' => 300, 'scope' => 'read write'], $result->toArray());
        self::assertNull($result->reason);
        self::assertNull($result->error);
        self::assertSame(200, $response->getStatusCode());
        self::assertSame($result->toArray(), $response->getData(true));
        self::assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
        self::assertSame('no-cache', $response->headers->get('Pragma'));
        self::assertFalse($response->headers->has('Retry-After'));
        self::assertFalse($response->headers->has('WWW-Authenticate'));
        self::assertSame(['access_token' => 't', 'token_type' => 'Bearer', 'expires_in' => 1], ClientCredentialsResult::granted('t', 1, [])->toArray());
    }

    /**
     * Rows of `[error, status]`.
     *
     * @return iterable<string, array{0: string, 1: int}>
     */
    public static function provideErrors(): iterable
    {
        yield from [
            'invalid_request'        => [ClientCredentialsResult::INVALID_REQUEST, 400],
            'invalid_client'         => [ClientCredentialsResult::INVALID_CLIENT, 401],
            'unauthorized_client'    => [ClientCredentialsResult::UNAUTHORIZED_CLIENT, 400],
            'unsupported_grant_type' => [ClientCredentialsResult::UNSUPPORTED_GRANT_TYPE, 400],
            'invalid_scope'          => [ClientCredentialsResult::INVALID_SCOPE, 400],
            'slow_down'              => [ClientCredentialsResult::SLOW_DOWN, 429],
        ];
    }

    /**
     * Each error answers RFC 6749's body with its status, never cached.
     *
     * @param  string  $error
     * @param  int  $status
     * @return void
     */
    #[DataProvider('provideErrors')]
    public function testAnErrorIsItsErrorResponse(string $error, int $status): void
    {
        $result   = ClientCredentialsResult::failed(FailureReason::CREDENTIAL_INVALID, $error);
        $response = $result->toResponse(Request::create('/'));

        self::assertFalse($result->isGranted());
        self::assertSame(['error' => $error], $result->toArray());
        self::assertSame($status, $response->getStatusCode());
        self::assertSame('no-cache', $response->headers->get('Pragma'));
        self::assertNull($result->accessToken);
        self::assertNull($result->expiresIn);
        self::assertNull($result->scopes);
    }

    /**
     * A wait answers `Retry-After`, and a Basic client's `invalid_client` a
     * challenge naming the realm.
     *
     * @return void
     */
    public function testAWaitAndAChallengeAreHeaders(): void
    {
        $slow = ClientCredentialsResult::failed(FailureReason::RATE_LIMITED, ClientCredentialsResult::SLOW_DOWN, 42)->toResponse(Request::create('/'));

        self::assertSame('42', $slow->headers->get('Retry-After'));

        $basic = ClientCredentialsResult::failed(FailureReason::CREDENTIAL_INVALID, ClientCredentialsResult::INVALID_CLIENT, null, 'm2m');

        self::assertSame('Basic realm="m2m"', $basic->toResponse(Request::create('/'))->headers->get('WWW-Authenticate'));
        self::assertSame(42, ClientCredentialsResult::failed(FailureReason::RATE_LIMITED, ClientCredentialsResult::SLOW_DOWN, 42)->retryAfter);
    }

    /**
     * A dump of a grant shows the token only as the caller holds it; the token
     * is a constructor's sensitive parameter.
     *
     * @return void
     */
    public function testTheTokenIsASensitiveParameter(): void
    {
        $parameter = new \ReflectionParameter([ClientCredentialsResult::class, '__construct'], 'accessToken');

        self::assertNotSame([], $parameter->getAttributes(\SensitiveParameter::class));
    }
}
