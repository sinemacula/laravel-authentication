<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched when the API key service rotates a key, once the replacement and
 * the replaced key's new expiry are committed on the keys' own connection,
 * never for a rotation that is rolled back. Both keys authenticate until the
 * replaced key's overlap ends; it then fails as `credential_expired`.
 *
 * The context describes the new key: its guard, the client of the request that
 * rotated it, its owner when the guard's provider still finds it, its principal
 * and that principal's tenant, its id in `credentialId` and its scopes, which
 * are the replaced key's. `previousKeyId` names the replaced key. Never a key,
 * a secret or a digest.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ApiKeyRotated extends ContextEvent
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\EventContext  $context
     * @param  string  $previousKeyId
     */
    public function __construct(

        // The new key and whose it is.
        EventContext $context,

        /** Identifier of the key the new one replaces. */
        public string $previousKeyId,
    ) {
        parent::__construct($context);
    }
}
