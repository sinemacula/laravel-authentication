<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Resolvers;

/**
 * Thrown by `DefaultPrincipalResolver::resolve()` when the supplied
 * identity implements neither `Principal` nor `HasPrincipals` and the
 * resolver therefore has no way to derive an acting principal for it.
 *
 * Surfaces as a programmer-error signal: the identity model is
 * misconfigured (it should implement at least one of the two
 * contracts) and the consumer must fix the model. The package's
 * guards catch this exception inside the authentication flow and
 * convert it into a standard `Failed` auth event so the request
 * surfaces as a 401 rather than a 500 — but the typed exception is
 * still preserved so consumer error reporters can attribute the
 * misconfiguration cleanly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited.
 */
final class UnresolvableIdentityException extends \LogicException {}
