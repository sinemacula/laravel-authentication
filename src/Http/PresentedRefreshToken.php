<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource;
use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * A refresh token a request carried, with where it carried it and every carrier
 * the request carried a refresh token in.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PresentedRefreshToken
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret  $token
     * @param  \SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource  $source
     * @param  list<\SineMacula\Laravel\Authentication\Http\Enums\RefreshTokenSource>  $carriers
     */
    public function __construct(

        /** The refresh token, as the request carried it. */
        public Secret $token,

        /** Where the request carried it. */
        public RefreshTokenSource $source,

        /** Every carrier the request carried a refresh token in, once per token. */
        public array $carriers,
    ) {}

    /**
     * The refresh token a body application's own code read from its request's
     * body.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string  $token
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromBody(#[\SensitiveParameter] Secret|string $token): self
    {
        return new self($token instanceof Secret ? $token : new Secret($token), RefreshTokenSource::BODY, [RefreshTokenSource::BODY]);
    }
}
