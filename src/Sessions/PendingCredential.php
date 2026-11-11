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
 * to the session service as a plain value.
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
     * Extract the pending credential from the request body; `null` when none
     * was presented, `pending_invalid` when it is not a non-empty string.
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
