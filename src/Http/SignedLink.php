<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use Illuminate\Http\Request;

/**
 * A signed link as a request to it arrived, held as plain values for the
 * service that consumes it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SignedLink
{
    /** @var \SensitiveParameterValue The query string as received, undecoded, with the link's fields and signature. */
    private \SensitiveParameterValue $query;

    /**
     * Constructor.
     *
     * @param  string  $url
     * @param  string  $query
     */
    public function __construct(

        /** The absolute address the link was signed for, without its query string. */
        public string $url,

        // The query string as received, undecoded
        #[\SensitiveParameter]
        string $query,
    ) {
        $this->query = new \SensitiveParameterValue($query);
    }

    /**
     * The signed link the request arrived at, with its query string as sent.
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
     * The query string as received, undecoded: the link's credential.
     *
     * @return string
     */
    public function query(): string
    {
        return $this->query->getValue();
    }

    /**
     * The request the link names, rebuilt from these values alone, for the
     * framework's signature and expiry checks.
     *
     * @return \Illuminate\Http\Request
     *
     * @internal
     */
    public function toRequest(): Request
    {
        $query = $this->query();

        parse_str($query, $fields);

        $request = Request::create($this->url, parameters: $fields);

        $request->server->set('QUERY_STRING', $query);

        return $request;
    }
}
