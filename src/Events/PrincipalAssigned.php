<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Events;

/**
 * Dispatched when a principal is bound to a guard during authentication, after
 * Laravel's `Authenticated`. The whole context is bound before either is
 * dispatched, so a listener that reads the guard sees the identity, principal
 * and device the event reports.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class PrincipalAssigned extends ContextEvent {}
