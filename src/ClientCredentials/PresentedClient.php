<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ClientCredentials;

use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyToken;
use SineMacula\Laravel\Authentication\ClientCredentials\Enums\ClientAuthentication;

/**
 * What a client credentials token request presented: the client's id and
 * secret, the scope it asked for, and how it authenticated the client.
 *
 * `ClientCredentialsRequest::extract()` builds one from a token request, and is
 * the way a controller should take one. An application may instead build one as
 * its trusted description of a request it read itself, as a `ClientContext`
 * built from plain values is; the exchange judges it on the facts given (a
 * `client_secret_post` the application does not allow is refused), but cannot
 * see facts left out, such as Basic credentials sent beside the body ones,
 * which `extract()` refuses.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PresentedClient
{
    /** @var \SensitiveParameterValue The client secret: the API key's secret, kept out of every dump and stack trace. */
    private \SensitiveParameterValue $clientSecret;

    /**
     * Constructor.
     *
     * @param  string  $clientId
     * @param  string  $clientSecret
     * @param  ?string  $scope
     * @param  \SineMacula\Laravel\Authentication\ClientCredentials\Enums\ClientAuthentication  $authentication
     */
    public function __construct(

        /** The client id: an API key's public part. */
        public string $clientId,

        // The client secret: the API key's secret.
        #[\SensitiveParameter]
        string $clientSecret,

        /** The scope requested, space-separated, or `null` for every granted scope. */
        public ?string $scope,

        /** How the request authenticated the client: HTTP Basic, or in the body. */
        public ClientAuthentication $authentication,
    ) {
        $this->clientSecret = new \SensitiveParameterValue($clientSecret);
    }

    /**
     * The client secret: the API key's secret.
     *
     * @return string
     */
    public function clientSecret(): string
    {
        return $this->clientSecret->getValue();
    }

    /**
     * The client id as events may report it: as given when it is an API key's
     * public part in form, otherwise `null`. A client that sends its whole key
     * as the id, or swaps the id and the secret, would otherwise have the
     * secret written to every listener that records failures.
     *
     * @return ?string
     */
    public function reportedId(): ?string
    {
        return ApiKeyToken::isPublicPart($this->clientId) ? $this->clientId : null;
    }
}
