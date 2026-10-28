<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Resolvers;

/**
 * Thrown by `DefaultPrincipalResolver::resolve()` when the identity implements
 * neither `Principal` nor `HasPrincipals`.
 *
 * Programmer-error signal: the identity model is misconfigured. Guards and the
 * refresh exchange let it propagate on every path (credential attempts, bearer
 * resolution and refresh), so it surfaces as a server error and reaches error
 * reporters instead of being reported as a failed authentication.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class UnresolvableIdentityException extends \LogicException {}
