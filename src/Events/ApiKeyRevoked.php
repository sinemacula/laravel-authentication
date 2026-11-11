<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched once an API key's revocation is committed.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ApiKeyRevoked extends ContextEvent {}
