<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ClientCredentials;

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

        /** The client secret: the API key's secret. */
        #[\SensitiveParameter]
        public string $clientSecret,

        /** The scope requested, space-separated, or `null` for every granted scope. */
        public ?string $scope,

        /** Whether the client authenticated with HTTP Basic. */
        public bool $basic,
    ) {}
}
