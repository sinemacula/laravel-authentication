<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\IdentifierChanges;

use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;
use SineMacula\Laravel\Authentication\Models\IdentifierChange;

/**
 * The fields of a validly signed, unexpired change link a request carries, as
 * given: none is trusted until the pending change it names is read and matched.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PresentedChangeLink
{
    /**
     * Constructor.
     *
     * @param  string  $guard
     * @param  string  $identity
     * @param  string  $type
     * @param  string  $requestId
     * @param  string  $hash
     */
    public function __construct(

        /** Guard the change was requested through. */
        public string $guard,

        /** Auth identifier of the identity whose identifier would change. */
        public string $identity,

        /** Type of the identifier. */
        public string $type,

        /** The change request the link confirms. */
        public string $requestId,

        /** SHA-256 digest of the new identifier in its normal form. */
        public string $hash,
    ) {}

    /**
     * The fields of the request's query, when each is a string and the type a
     * valid identifier type; otherwise `null`.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return ?self
     */
    public static function of(Request $request): ?self
    {
        $guard     = $request->query('guard');
        $identity  = $request->query('identity');
        $type      = $request->query('type');
        $requestId = $request->query('request');
        $hash      = $request->query('hash');

        if (!is_string($guard) || !is_string($identity) || !is_string($type)) {
            return null;
        }

        return is_string($requestId) && is_string($hash) && IdentifierType::isValid($type) ? new self($guard, $identity, $type, $requestId, $hash) : null;
    }

    /**
     * Whether the link names the pending change as it stands: the same request
     * and the same new identifier, compared in constant time.
     *
     * @param  \SineMacula\Laravel\Authentication\Models\IdentifierChange  $change
     * @return bool
     */
    public function names(IdentifierChange $change): bool
    {
        return hash_equals($change->request_id, $this->requestId) && hash_equals(ChangeLinks::digest($change->identifier), $this->hash);
    }
}
