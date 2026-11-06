<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use Illuminate\Http\Request;

/**
 * A signed link as a request to it arrived, held as plain values for the
 * service that consumes it: the absolute address the link was signed for
 * (scheme, host, port, base path and path, as Laravel signs them, behind the
 * application's trusted proxies) and the raw query string as received, which
 * carries the link's fields, its expiry and its signature.
 *
 * `fromRequest()` captures one from the request a controller serves, and is the
 * way a controller should take one. The service that consumes it never trusts
 * it: it checks the signature and the expiry again from these values, with
 * every key the application signs with and every previous key
 * (`app.previous_keys`), so an address or a query changed on the way fails as a
 * link that was never signed. The query string is the credential: keep it out
 * of logs.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SignedLink
{
    /**
     * Constructor.
     *
     * @param  string  $url
     * @param  string  $query
     */
    public function __construct(

        /** The absolute address the link was signed for, without its query string. */
        public string $url,

        /** The query string as received, undecoded, with the link's fields and signature. */
        #[\SensitiveParameter]
        public string $query,
    ) {}

    /**
     * The signed link the request arrived at: its address as Laravel signs it,
     * through the application's trusted proxies, and its raw query string
     * (Vapor's raw one when it hands one over), so a query a proxy or the
     * framework would encode differently is checked as it was sent.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return self
     */
    public static function fromRequest(Request $request): self
    {
        $url   = rtrim($request->getSchemeAndHttpHost() . $request->getBaseUrl() . $request->getPathInfo(), '/');
        $query = $request->server->get('VAPOR_RAW_QUERY_STRING') ?? $request->server->get('QUERY_STRING');

        return new self($url, is_string($query) ? $query : '');
    }

    /**
     * The request the link names, rebuilt from these values alone, for the
     * framework's signature and expiry checks: the address as given and the raw
     * query string, its fields parsed from it.
     *
     * @return \Illuminate\Http\Request
     *
     * @internal
     */
    public function toRequest(): Request
    {
        $request = Request::create($this->url);

        parse_str($this->query, $fields);

        $request->server->set('QUERY_STRING', $this->query);
        $request->query->replace($fields);

        return $request;
    }
}
