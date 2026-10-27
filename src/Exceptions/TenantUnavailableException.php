<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Exceptions;

/**
 * Thrown by `Principal::getTenant()` when the principal names a tenant that
 * cannot be loaded: deleted, soft-deleted, or hidden by a global scope.
 *
 * The activation policy reads it as an inactive tenant, so the principal cannot
 * authenticate, rather than as a principal that acts within no tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class TenantUnavailableException extends \RuntimeException {}
