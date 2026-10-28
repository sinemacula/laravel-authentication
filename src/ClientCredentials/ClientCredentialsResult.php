<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ClientCredentials;

use Illuminate\Contracts\Support\Arrayable;
use Illuminate\Contracts\Support\Responsable;
use Illuminate\Http\JsonResponse;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Scopes\Scopes;

/**
 * How a client credentials exchange ended: an access token with its lifetime
 * and scopes (RFC 6749 section 5.1), or an error (section 5.2) with the reason
 * the server-side event carries. As a response it answers in RFC 6749's shapes
 * with `Cache-Control: no-store` and `Pragma: no-cache`: 200 with the token;
 * 400 for `invalid_request`, `unsupported_grant_type`, `unauthorized_client`
 * and `invalid_scope`; 401 for `invalid_client`, with `WWW-Authenticate: Basic`
 * when the client authenticated with HTTP Basic; and 429 with `Retry-After` for
 * `slow_down`, a registered OAuth error (RFC 8628) the package answers a client
 * past its limit with, since RFC 6749 defines no rate-limit error.
 *
 * Routes are the application's: return the result from a controller, or read
 * its parts. `toArray()` and JSON give the response body alone, so the reason
 * the server-side event carries never reaches the client however the result is
 * encoded.
 *
 * @api
 *
 * @implements \Illuminate\Contracts\Support\Arrayable<string, mixed>
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ClientCredentialsResult implements \JsonSerializable, Arrayable, Responsable
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
     * @param  ?string  $accessToken
     * @param  ?int  $expiresIn
     * @param  ?list<string>  $scopes
     * @param  ?\SineMacula\Laravel\Authentication\Events\Enums\FailureReason  $reason
     * @param  ?string  $error
     * @param  ?int  $retryAfter
     * @param  ?string  $basicRealm
     */
    private function __construct(

        /** The access token, when one was issued. */
        #[\SensitiveParameter]
        public ?string $accessToken = null,

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

        /** The realm of the `WWW-Authenticate: Basic` challenge, for a client that authenticated with HTTP Basic and failed to. */
        private ?string $basicRealm = null,
    ) {}

    /**
     * An exchange that issued an access token.
     *
     * @param  string  $accessToken
     * @param  int  $expiresIn
     * @param  list<string>  $scopes
     * @return self
     */
    public static function granted(#[\SensitiveParameter] string $accessToken, int $expiresIn, array $scopes): self
    {
        return new self($accessToken, $expiresIn, $scopes);
    }

    /**
     * An exchange that failed with the reason and the error the client is
     * answered with, the wait for `slow_down`, and the realm of the Basic
     * challenge for a client that authenticated with HTTP Basic.
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
     * The response body: RFC 6749 section 5.1 for a token, section 5.2 for an
     * error. A token granting no scope has no `scope` member, since RFC 6749
     * section 3.3 defines a scope value as one or more scope tokens.
     *
     * @return array{access_token: string, token_type: string, expires_in: ?int, scope?: string}|array{error: ?string}
     */
    #[\Override]
    public function toArray(): array
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
     * The result as JSON serialises it: the response body, as `toArray()` gives
     * it.
     *
     * @return array{access_token: string, token_type: string, expires_in: ?int, scope?: string}|array{error: ?string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->toArray();
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
        $response = new JsonResponse($this->toArray(), $this->status(), ['Cache-Control' => 'no-store', 'Pragma' => 'no-cache']);

        if ($this->retryAfter !== null) {
            $response->headers->set('Retry-After', (string) $this->retryAfter);
        }

        if ($this->basicRealm !== null) {
            $response->headers->set('WWW-Authenticate', sprintf('Basic realm="%s"', $this->basicRealm));
        }

        return $response;
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
