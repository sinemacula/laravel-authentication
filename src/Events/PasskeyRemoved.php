<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched once the removal of an identity's passkey is committed.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PasskeyRemoved extends ContextEvent {}
