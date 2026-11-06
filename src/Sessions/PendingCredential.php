<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Illuminate\Container\Container;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Http\RequestBody;
use SineMacula\Laravel\Authentication\Secrets\Secret;

/**
 * Reads the pending credential a request presents, for a controller to hand on
 * to the session service as a plain value, as
 * `RefreshTokenTransport::extract()` reads a refresh token for `refresh()`:
 * `satisfy()` and `choose()` take what it answered once the controller has
 * answered a `null` (nothing presented), the `Secret` or `pending_invalid`
 * alike; `pending()` and `discard()` take only the `Secret`, so a controller
 * answers anything else itself.
 *
 * The credential travels only in the body field
 * `session.pending_credential_field` names: the JSON body, or the form body of
 * a method that may have one (`RequestBody::fields()`), never the query string
 * or a header, so it never lands in a URL that logs and histories keep.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class PendingCredential
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Extract the pending credential the request presents: `null` when the body
     * has no such field, so nothing was presented and nothing is to be
     * reported; `pending_invalid` when the field is not a non-empty string;
     * otherwise the credential as a `Secret`. A field name PHP would file under
     * another key fails closed (`InvalidArgumentException`). Extracting has no
     * side effects: it reports nothing and reads no IP address.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \SineMacula\Laravel\Authentication\Events\Enums\FailureReason|\SineMacula\Laravel\Authentication\Secrets\Secret|null
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    public static function extract(Request $request): FailureReason|Secret|null
    {
        $body  = RequestBody::fields($request);
        $field = PendingState::credentialField(Container::getInstance()->make(Repository::class));

        if (!array_key_exists($field, $body)) {
            return null;
        }

        $credential = $body[$field];

        return is_string($credential) && $credential !== '' ? new Secret($credential) : FailureReason::PENDING_INVALID;
    }
}
