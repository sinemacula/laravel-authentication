<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched when the API key service revokes a key, once the revocation is
 * committed on the key's own connection: only by the call that revoked it, not
 * for a key that was already revoked, and never for a revocation that is rolled
 * back. The key, and every access token a client credentials exchange issued
 * from it, stops authenticating at once.
 *
 * The context carries the key's guard, the client of the request that revoked
 * it, its owner when the guard's provider still finds it, the principal it
 * acted as and that principal's tenant, the key's id in `credentialId` and its
 * scopes. Never the key, its secret or its digest.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ApiKeyRevoked extends ContextEvent {}
