<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Resolvers;

/**
 * Thrown by `DefaultPrincipalResolver::resolve()` when the identity implements
 * neither `Principal` nor `HasPrincipals`.
 *
 * Programmer-error signal: the identity model is misconfigured. Guards catch
 * this inside the auth flow and convert it into a standard `Failed` event so
 * the request surfaces as 401, but the typed exception is preserved for error
 * reporters.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class UnresolvableIdentityException extends \LogicException {}
