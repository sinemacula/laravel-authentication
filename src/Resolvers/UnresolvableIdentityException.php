<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Resolvers;

/**
 * Thrown by `DefaultPrincipalResolver::resolve()` when the identity implements
 * neither `Principal` nor `HasPrincipals`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class UnresolvableIdentityException extends \LogicException {}
