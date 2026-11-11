<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ClientCredentials;

use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyToken;
use SineMacula\Laravel\Authentication\ClientCredentials\Enums\ClientAuthentication;

/**
 * What a client credentials token request presented: the client's id and
 * secret, the scope it asked for, and how it authenticated the client.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PresentedClient
{
    /** @var \SensitiveParameterValue The API key's secret, kept out of dumps and stack traces. */
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
     * The client id when it is a well-formed public part, else `null`, so a
     * secret sent as the id is never reported.
     *
     * @return ?string
     */
    public function reportedId(): ?string
    {
        return ApiKeyToken::isPublicPart($this->clientId) ? $this->clientId : null;
    }
}
