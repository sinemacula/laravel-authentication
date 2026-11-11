<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ClientCredentials;

use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Scopes\Scopes;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Secrets\SecretResponse;

/**
 * How a client credentials exchange ended: an access token (RFC 6749 section
 * 5.1) or an error (section 5.2), answered as a `no-store` response.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ClientCredentialsResult implements \JsonSerializable, Responsable
{
    /** @var string Error for a malformed request. */
    public const string INVALID_REQUEST = 'invalid_request';

    /** @var string Error for a client that failed to authenticate. */
    public const string INVALID_CLIENT = 'invalid_client';

    /** @var string Error for a client not allowed this grant on the guard. */
    public const string UNAUTHORIZED_CLIENT = 'unauthorized_client';

    /** @var string Error for a grant type other than `client_credentials`. */
    public const string UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type';

    /** @var string Error for a scope that is malformed or not granted to the client. */
    public const string INVALID_SCOPE = 'invalid_scope';

    /** @var string Error for a client past its limit, with `Retry-After`. */
    public const string SLOW_DOWN = 'slow_down';

    /**
     * Constructor.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Secrets\Secret  $accessToken
     * @param  ?int  $expiresIn
     * @param  ?list<string>  $scopes
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?string  $error
     * @param  ?int  $retryAfter
     * @param  ?string  $basicRealm
     */
    private function __construct(

        /** The access token, when one was issued. */
        public ?Secret $accessToken = null,

        /** Seconds until the access token expires, when one was issued. */
        public ?int $expiresIn = null,

        /** The scopes the access token grants, when one was issued. */
        public ?array $scopes = null,

        /** Why the exchange failed, as the server-side event says, when it did. */
        public ?FailureReason $reason = null,

        /** The RFC 6749 error the client is answered with, when the exchange failed. */
        public ?string $error = null,

        /** Seconds until the client may try again, for `slow_down` only. */
        public ?int $retryAfter = null,

        /** The realm of the `WWW-Authenticate: Basic` challenge an `invalid_client` answer carries. */
        private ?string $basicRealm = null,
    ) {}

    /**
     * An exchange that issued an access token.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $accessToken
     * @param  int  $expiresIn
     * @param  list<string>  $scopes
     * @return self
     */
    public static function granted(Secret $accessToken, int $expiresIn, array $scopes): self
    {
        return new self($accessToken, $expiresIn, $scopes);
    }

    /**
     * An exchange that failed with the reason and the error the client is
     * answered with.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  string  $error
     * @param  ?int  $retryAfter
     * @param  ?string  $basicRealm
     * @return self
     */
    public static function failed(FailureReason $reason, string $error, ?int $retryAfter = null, ?string $basicRealm = null): self
    {
        return new self(reason: $reason, error: $error, retryAfter: $retryAfter, basicRealm: $basicRealm);
    }

    /**
     * Whether an access token was issued.
     *
     * @return bool
     */
    public function isGranted(): bool
    {
        return $this->accessToken !== null;
    }

    /**
     * The response body with the access token revealed, for a response that
     * must not be stored.
     *
     * @return array{access_token: string, token_type: string, expires_in: ?int, scope?: string}|array{error: ?string}
     */
    public function toArray(): array
    {
        $body = $this->body();

        return isset($body['access_token']) ? [...$body, 'access_token' => $body['access_token']->reveal()] : $body;
    }

    /**
     * The response body with the access token unrevealed, so a granted result
     * refuses to encode.
     *
     * @return array{access_token: \SineMacula\Laravel\Authentication\Secrets\Secret, token_type: string, expires_in: ?int, scope?: string}|array{error: ?string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->body();
    }

    /**
     * The HTTP response, never cached.
     *
     * @param  mixed  $request
     * @return \Illuminate\Http\JsonResponse
     */
    #[\Override]
    public function toResponse(mixed $request): JsonResponse
    {
        $response = SecretResponse::json($this->body(), $this->status());

        if ($this->retryAfter !== null) {
            $response->headers->set('Retry-After', (string) $this->retryAfter);
        }

        if ($this->basicRealm !== null) {
            $response->headers->set('WWW-Authenticate', sprintf('Basic realm="%s"', $this->basicRealm));
        }

        return $response;
    }

    /**
     * The response body, with the access token still a secret.
     *
     * @return array{access_token: \SineMacula\Laravel\Authentication\Secrets\Secret, token_type: string, expires_in: ?int, scope?: string}|array{error: ?string}
     */
    private function body(): array
    {
        if ($this->accessToken === null) {
            return ['error' => $this->error];
        }

        $scopes = $this->scopes ?? [];
        $body   = [
            'access_token' => $this->accessToken,
            'token_type'   => 'Bearer',
            'expires_in'   => $this->expiresIn,
        ];

        return $scopes === [] ? $body : [...$body, 'scope' => Scopes::format($scopes)];
    }

    /**
     * The HTTP status the result answers with.
     *
     * @return int
     */
    private function status(): int
    {
        return match ($this->error) {
            null                 => 200,
            self::INVALID_CLIENT => 401,
            self::SLOW_DOWN      => 429,
            default              => 400,
        };
    }
}
