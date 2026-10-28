<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ClientCredentials;

use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyToken;

/**
 * What a client credentials token request presented: the client's id and
 * secret, the scope it asked for, and whether it authenticated with HTTP Basic.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
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
     * @param  bool  $basic
     */
    public function __construct(

        /** The client id: an API key's public part. */
        public string $clientId,

        // The client secret: the API key's secret, held out of every dump.
        #[\SensitiveParameter]
        string $clientSecret,

        /** The scope requested, space-separated, or `null` for every granted scope. */
        public ?string $scope,

        /** Whether the client authenticated with HTTP Basic. */
        public bool $basic,
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
