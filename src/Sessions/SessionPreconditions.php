<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use SineMacula\Laravel\Authentication\Contracts\HasDevices;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;

/**
 * Checks the session service makes of what a caller hands it, before anything
 * is signed in: that a session can be started for the identity at all, which
 * principal a session for an externally verified identity is pinned to, and
 * whether the guard's provider returned the very identity that was verified.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SessionPreconditions
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * Refuse an identity that does not own devices: a session lives on a
     * device, and a bearer token names one the guard can only find through the
     * identity's `HasDevices` relation, so its access token would never
     * authenticate. Such a guard is access-only and signs in with `attempt()`.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return void
     *
     * @throws \LogicException
     */
    public static function assertHoldsDevices(Identity $identity): void
    {
        if ($identity instanceof HasDevices) {
            return;
        }

        $message = sprintf(
            'The session service can only start sessions for identities that implement %s; %s does not. '
            . 'Sign this guard\'s identities in with attempt() and issue access tokens instead.',
            HasDevices::class,
            $identity::class,
        );

        throw new \LogicException($message);
    }

    /**
     * The principal a session started for an externally verified identity is
     * pinned to: the one given as the argument or on the context, which must
     * not both name one.
     *
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Sessions\SignInContext  $context
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Principal
     *
     * @throws \InvalidArgumentException
     */
    public static function pinnedPrincipal(?Principal $principal, SignInContext $context): ?Principal
    {
        if ($principal === null) {
            return $context->principal;
        }

        if ($context->principal !== null) {
            throw new \InvalidArgumentException('Name the principal to start a session as either as the argument or on the context, not both.');
        }

        return $principal;
    }

    /**
     * Whether the provider's answer is the very identity the caller verified:
     * the same class with the same auth identifier.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $reloaded
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return bool
     */
    public static function isSameIdentity(Identity $reloaded, Identity $identity): bool
    {
        return $reloaded::class === $identity::class && IdentifierCoercion::matches($reloaded->getAuthIdentifier(), $identity->getAuthIdentifier());
    }
}
