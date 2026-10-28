<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched when the API key service issues a key, once the new row is
 * committed on the key's own connection (never for one that is rolled back).
 *
 * The context carries the guard the key authenticates for, the client of the
 * request that issued it, the non-human identity that owns it, the principal it
 * acts as and that principal's tenant, the key's id in `credentialId` and the
 * scopes it grants. Never the key, its secret or its digest.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ApiKeyIssued extends ContextEvent {}
