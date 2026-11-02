<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use Illuminate\Http\Request;

/**
 * The body a credential is read from: a refresh token's `body_field` and the
 * pending credential's `session.pending_credential_field` alike.
 *
 * The fields are the JSON body, or the form body of a request that may have
 * one, never the query string, so a credential never travels in a URL that
 * logs, histories and `Referer` headers keep. A field name is one PHP files as
 * it is in a form body: a `.` or a space would be filed as `_` and a bracket
 * would nest it, so a field named so would never be found.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RequestBody
{
    /** @var string A field name PHP keeps as it is in a form body: no whitespace, `.`, brackets or control characters. */
    private const string FIELD_PATTERN = '/^[^\s.\[\]\x00-\x1F\x7F]+$/D';

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The request's body fields: the JSON body, or the form body of a request
     * that may have one; never the query string.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array<array-key, mixed>
     */
    public static function fields(Request $request): array
    {
        if ($request->isJson()) {
            return $request->json()->all();
        }

        return in_array($request->getRealMethod(), ['GET', 'HEAD'], true) ? [] : $request->request->all();
    }

    /**
     * Whether the value is a field name PHP keeps as it is in a form body.
     *
     * @param  mixed  $name
     * @return bool
     *
     * @phpstan-assert-if-true string $name
     */
    public static function isFieldName(mixed $name): bool
    {
        return is_string($name) && preg_match(self::FIELD_PATTERN, $name) === 1;
    }
}
