<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\ClientCredentials;

use Illuminate\Http\Request;

/**
 * Reads a client credentials token request as RFC 6749 sections 2.3.1, 3.2 and
 * 4.4.2 define it: a POST with an `application/x-www-form-urlencoded` body
 * carrying `grant_type=client_credentials`, an optional `scope`, and the client
 * authenticated either with HTTP Basic (the id and secret each
 * form-url-encoded) or with `client_id` and `client_secret` in the body, never
 * both. Every parameter comes from the body: one in the query string, given
 * more than once, or not a string is refused rather than ignored, so a
 * credential in a URL never authenticates.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ClientCredentialsRequest
{
    /** @var list<string> The parameters the request may carry, each at most once, in the body. */
    private const array PARAMETERS = ['grant_type', 'scope', 'client_id', 'client_secret'];

    /** @var string The only media type the body may have. */
    private const string FORM = 'application/x-www-form-urlencoded';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * What the request presented, or the RFC 6749 error it is refused with:
     * `invalid_request` for a request that is not one in form,
     * `unsupported_grant_type` for another grant, and `invalid_client` for a
     * request without client authentication or with malformed Basic
     * credentials.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\ClientCredentials\PresentedClient|string
     */
    public static function read(Request $request): PresentedClient|string
    {
        $parameters = self::parameters($request);
        $grant      = $parameters['grant_type'] ?? null;

        if ($grant !== ClientCredentialsExchange::GRANT_TYPE) {
            return $grant === null ? ClientCredentialsResult::INVALID_REQUEST : ClientCredentialsResult::UNSUPPORTED_GRANT_TYPE;
        }

        return self::client($request, $parameters);
    }

    /**
     * Whether the request authenticated, or tried to, with HTTP Basic.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    public static function usesBasic(Request $request): bool
    {
        return self::basicCredentials($request) !== null;
    }

    /**
     * The client the request authenticated as, with the scope it asked for, or
     * the error it is refused with.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  array<string, string>  $parameters
     * @return \SineMacula\Laravel\Authentication\ClientCredentials\PresentedClient|string
     */
    private static function client(Request $request, #[\SensitiveParameter] array $parameters): PresentedClient|string
    {
        $basic  = self::basicCredentials($request);
        $inBody = array_key_exists('client_id', $parameters) || array_key_exists('client_secret', $parameters);

        if ($basic !== null && $inBody) {
            return ClientCredentialsResult::INVALID_REQUEST;
        }

        $credentials = $basic === null ? self::body($parameters) : self::basic($basic);

        return $credentials === null
            ? ClientCredentialsResult::INVALID_CLIENT
            : new PresentedClient($credentials[0], $credentials[1], $parameters['scope'] ?? null, $basic !== null);
    }

    /**
     * The credentials of the request's HTTP Basic authorization (empty for the
     * bare scheme), or `null` when it uses another scheme or none.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return ?string
     */
    private static function basicCredentials(Request $request): ?string
    {
        return preg_match('/^Basic(?: (.*))?$/i', (string) $request->headers->get('Authorization'), $matches) === 1 ? $matches[1] ?? '' : null;
    }

    /**
     * The client id and secret in the body, or `null` unless both are there.
     *
     * @param  array<string, string>  $parameters
     * @return ?array{0: string, 1: string}
     */
    private static function body(#[\SensitiveParameter] array $parameters): ?array
    {
        $id     = $parameters['client_id']     ?? null;
        $secret = $parameters['client_secret'] ?? null;

        return $id === null || $secret === null ? null : [$id, $secret];
    }

    /**
     * The client id and secret of Basic credentials, each form-url-decoded, or
     * `null` for credentials that are not base64 of `id:secret` (the secret may
     * itself contain a colon).
     *
     * @param  string  $credentials
     * @return ?array{0: string, 1: string}
     */
    private static function basic(#[\SensitiveParameter] string $credentials): ?array
    {
        $decoded = base64_decode($credentials, true);
        $pair    = $decoded === false ? [] : explode(':', $decoded, 2);

        return count($pair) === 2 ? [urldecode($pair[0]), urldecode($pair[1])] : null;
    }

    /**
     * The request's parameters, read from a form-encoded POST body, or none
     * when the request is not one in form (so it names no grant): not a POST, a
     * body of another media type, a parameter in the query string, given twice,
     * or not a string.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array<string, string>
     */
    private static function parameters(Request $request): array
    {
        $type = strtolower(trim(explode(';', (string) $request->headers->get('Content-Type'))[0]));

        if (!$request->isMethod('POST') || $type !== self::FORM || self::repeats($request)) {
            return [];
        }

        $names      = array_flip(self::PARAMETERS);
        $parameters = array_filter(array_intersect_key($request->request->all(), $names), static fn (mixed $value): bool => $value !== null);
        $inQuery    = array_intersect_key($request->query->all(), $names);

        $strings = array_filter($parameters, is_string(...));

        return $inQuery === [] && count($strings) === count($parameters) ? $strings : [];
    }

    /**
     * Whether the raw body names a parameter more than once, which PHP would
     * otherwise read as its last value.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return bool
     */
    private static function repeats(Request $request): bool
    {
        $names = [];

        foreach (explode('&', $request->getContent()) as $pair) {
            $names[] = self::name($pair);
        }

        $named = array_intersect($names, self::PARAMETERS);

        return count($named) !== count(array_unique($named));
    }

    /**
     * The name of a pair of a form body as PHP's form parser registers it:
     * decoded, cut at a NUL byte, leading spaces dropped, a `.` or space read
     * as `_`, and cut at a `[` that a `]` follows, or else with the `[` and
     * every `.`, space and `[` after it read as `_`. It is worked out here
     * rather than with `parse_str()`, which also splits on whatever else
     * `arg_separator.input` holds, while a form body is split on `&` alone.
     *
     * @param  string  $pair
     * @return string
     */
    private static function name(string $pair): string
    {
        $name          = ltrim(explode("\0", urldecode(explode('=', $pair)[0]))[0], ' ');
        [$base, $rest] = explode('[', $name, 2) + [1 => null];
        $base          = strtr($base, ' .', '__');

        return $rest === null || str_contains($rest, ']') ? $base : $base . '_' . strtr($rest, ' .[', '___');
    }
}
