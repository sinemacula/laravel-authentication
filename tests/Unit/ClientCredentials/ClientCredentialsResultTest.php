<?php

declare(strict_types = 1);

namespace Tests\Unit\ClientCredentials;

use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsResult;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Exceptions\SecretNotRevealedException;
use SineMacula\Laravel\Authentication\Secrets\Secret;

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
        $result   = ClientCredentialsResult::granted(new Secret('token-value'), 300, ['read', 'write']);
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
        self::assertSame(['access_token' => 't', 'token_type' => 'Bearer', 'expires_in' => 1], ClientCredentialsResult::granted(new Secret('t'), 1, [])->toArray());
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
     * Each error answers RFC 6749's body with its status, never cached: the
     * code alone, with no `error_description`.
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
        self::assertSame(['error' => $error], $response->getData(true));
        self::assertSame($status, $response->getStatusCode());
        self::assertStringContainsString('no-store', (string) $response->headers->get('Cache-Control'));
        self::assertSame('no-cache', $response->headers->get('Pragma'));
        self::assertNull($result->accessToken);
        self::assertNull($result->expiresIn);
        self::assertNull($result->scopes);
    }

    /**
     * Encoded as JSON, a grant refuses: its token is a secret, which only
     * `toResponse()` (never stored) or `toArray()` reveals, so neither
     * `json_encode()` nor a JSON response built from the result can send the
     * token without `no-store`; nor does the result offer itself as an
     * `Arrayable`, which a JSON response would read without asking.
     *
     * @return void
     */
    public function testAGrantRefusesToEncodeAsJson(): void
    {
        $granted = ClientCredentialsResult::granted(new Secret('token-value'), 300, ['read']);

        self::assertNotInstanceOf(Arrayable::class, $granted);

        $this->expectException(SecretNotRevealedException::class);

        json_encode($granted, JSON_THROW_ON_ERROR);
    }

    /**
     * A JSON response built from a grant refuses too, rather than send the
     * token without `no-store`.
     *
     * @return void
     */
    public function testAJsonResponseOfAGrantRefuses(): void
    {
        $this->expectException(SecretNotRevealedException::class);

        new JsonResponse(ClientCredentialsResult::granted(new Secret('token-value'), 300, ['read']));
    }

    /**
     * Encoded as JSON, every failure of a client is the same `invalid_client`
     * body, so the reason only the server-side event carries never reaches the
     * client, alone or nested in another body.
     *
     * @return void
     */
    public function testAsJsonAFailureIsItsErrorBodyAlone(): void
    {
        $bodies = array_map(
            static fn (FailureReason $reason): false|string => json_encode(['result' => ClientCredentialsResult::failed($reason, ClientCredentialsResult::INVALID_CLIENT)]),
            [FailureReason::CREDENTIAL_INVALID, FailureReason::CREDENTIAL_REVOKED, FailureReason::CREDENTIAL_EXPIRED, FailureReason::IDENTITY_INACTIVE],
        );

        self::assertSame(['{"result":{"error":"invalid_client"}}'], array_values(array_unique($bodies)));
    }

    /**
     * A wait answers `Retry-After`, and `invalid_client` the Basic challenge
     * naming the realm it was given.
     *
     * @return void
     */
    public function testAWaitAndAChallengeAreHeaders(): void
    {
        $slow = ClientCredentialsResult::failed(FailureReason::RATE_LIMITED, ClientCredentialsResult::SLOW_DOWN, 42)->toResponse(Request::create('/'));

        self::assertSame('42', $slow->headers->get('Retry-After'));

        $challenged = ClientCredentialsResult::failed(FailureReason::CREDENTIAL_INVALID, ClientCredentialsResult::INVALID_CLIENT, null, 'm2m');

        self::assertSame('Basic realm="m2m"', $challenged->toResponse(Request::create('/'))->headers->get('WWW-Authenticate'));
        self::assertSame(42, ClientCredentialsResult::failed(FailureReason::RATE_LIMITED, ClientCredentialsResult::SLOW_DOWN, 42)->retryAfter);
    }

    /**
     * A grant holds its token as a secret, so no dump of the result shows it
     * and serialising the result throws.
     *
     * @return void
     */
    public function testAGrantHoldsItsTokenAsASecret(): void
    {
        $granted = ClientCredentialsResult::granted(new Secret('token-value'), 300, ['read']);

        self::assertInstanceOf(Secret::class, $granted->accessToken);
        self::assertSame('token-value', $granted->accessToken->reveal());
        self::assertStringNotContainsString('token-value', print_r($granted, true));

        $this->expectException(SecretNotRevealedException::class);

        serialize($granted);
    }
}
