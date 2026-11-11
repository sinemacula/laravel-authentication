<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Http;

use Illuminate\Http\Request;

/**
 * The body a credential is read from, never the query string.
 *
 * PHP files a `.` or space in a form field name as `_` and nests brackets, so
 * such a name is never found.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
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
     * The request's JSON body, or the form body of a request that may have one.
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
     *
     * @internal
     */
    public static function isFieldName(mixed $name): bool
    {
        return is_string($name) && preg_match(self::FIELD_PATTERN, $name) === 1;
    }
}
