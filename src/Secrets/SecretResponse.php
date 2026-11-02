<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Secrets;

use Illuminate\Http\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

/**
 * Responses that carry a secret: the only bodies a `Secret` is revealed into
 * without the caller revealing it, and always marked not to be stored, so no
 * browser, proxy or shared cache keeps a copy of the token, credential or key.
 *
 * Use `json()` for a body built from the package's results, and
 * `withoutStoring()` for a response built some other way. To cover every
 * response of a route, the secrets of other packages and error responses
 * included, place the `authentication.no-store` middleware on it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class SecretResponse
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * A JSON response of the data with every `Secret` in it, at any depth of
     * arrays, revealed, and with `Cache-Control: no-store` and `Pragma:
     * no-cache`, which replace any caching headers given.
     *
     * @param  array<array-key, mixed>  $data
     * @param  int  $status
     * @param  array<string, list<string>|string>  $headers
     * @return \Illuminate\Http\JsonResponse
     */
    public static function json(array $data, int $status = 200, array $headers = []): JsonResponse
    {
        return self::withoutStoring(new JsonResponse(self::revealed($data), $status, $headers));
    }

    /**
     * Mark the response not to be stored: `Cache-Control: no-store` and
     * `Pragma: no-cache`, replacing whatever caching it allowed.
     *
     * @template TResponse of \Symfony\Component\HttpFoundation\Response
     *
     * @param  TResponse  $response
     * @return TResponse
     */
    public static function withoutStoring(Response $response): Response
    {
        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');

        return $response;
    }

    /**
     * The data with every `Secret` in it, at any depth of arrays, revealed.
     *
     * @param  array<array-key, mixed>  $data
     * @return array<array-key, mixed>
     */
    private static function revealed(array $data): array
    {
        return array_map(static fn (mixed $value): mixed => match (true) {
            $value instanceof Secret => $value->reveal(),
            is_array($value)         => self::revealed($value),
            default                  => $value,
        }, $data);
    }
}
