<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Admission\ActivationPolicy;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\CodeIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\AudiencePolicy;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\MachineIdentity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\Enums\FailureReason;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;

/**
 * Who may reset a password with a link or code bound to an identifier: the
 * identity the guard's provider finds by it, read on the write connection, when
 * it is a stored Eloquent model that is not a machine identity, holds exactly
 * that identifier, is active, and, when the guard requires verified
 * identifiers, has it verified. The delivery job sends only to that identity,
 * and a reset sets only its password.
 *
 * Whether the identity holds the identifier is decided here, byte for byte and
 * in constant time on its canonical form, never by the lookup (see
 * `CodeIdentifiers`): through `HasVerifiableIdentifiers` when the identity
 * implements it, otherwise from the model attribute named by the type. Anyone
 * else is refused with the reason the failure event reports.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ResetRecipient
{
    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The identity that may reset its password with the binding, or why there
     * is none: `invalid_credentials` (no one, or no one holding exactly the
     * identifier), `machine_identity`, `identity_inactive` or
     * `identifier_unverified`.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity)|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function find(JwtGuard $guard, CodeBinding $binding, Container $container): FailureReason|(Identity&Model)
    {
        return self::eligible($guard, $guard->getProvider()->retrieveByCredentials([$binding->type => $binding->identifier]), $binding, $container);
    }

    /**
     * The identity found, when it may reset its password with the binding, or
     * why it may not (see `find()`): a reset calls it again on the row it
     * locked, so a deactivation committed since the lookup is not missed.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @param  mixed  $found
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity)|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function eligible(JwtGuard $guard, mixed $found, CodeBinding $binding, Container $container): FailureReason|(Identity&Model)
    {
        return match (true) {
            !$found instanceof Identity || !$found instanceof Model                     => FailureReason::INVALID_CREDENTIALS,
            $found instanceof MachineIdentity                                           => FailureReason::MACHINE_IDENTITY,
            !self::holds($found, $binding, $container->make(IdentifierVerifier::class)) => FailureReason::INVALID_CREDENTIALS,
            !ActivationPolicy::isActive($found)                                         => FailureReason::IDENTITY_INACTIVE,
            default                                                                     => self::verified($guard, $found, $binding->type, $container),
        };
    }

    /**
     * The identity's own identifier of the type, read on the write connection,
     * in canonical form: through `HasVerifiableIdentifiers` when the identity
     * implements it, otherwise from the model attribute named by the type;
     * `null` when it has none, or the model has no such attribute. An identity
     * whose verification cannot report the type at all may throw a
     * `LogicException` (`ProvidesIdentifierVerification` does, for a column the
     * model has not loaded).
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  \SineMacula\Laravel\Authentication\Verification\IdentifierVerifier  $verifier
     * @return ?string
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public static function identifierOf(Identity&Model $identity, string $type, IdentifierVerifier $verifier): ?string
    {
        if ($identity instanceof HasVerifiableIdentifiers) {
            return CodeIdentifiers::of($identity, $type, $verifier);
        }

        if (!$identity->hasAttribute($type)) {
            return null;
        }

        $own = WriteConnection::during($identity, static fn (): mixed => $identity->getAttribute($type));

        return is_string($own) ? $verifier->canonical($type, $own) : null;
    }

    /**
     * Whether the identity's own identifier of the binding's type is exactly
     * the bound one in canonical form.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  \SineMacula\Laravel\Authentication\Verification\IdentifierVerifier  $verifier
     * @return bool
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function holds(Identity&Model $identity, CodeBinding $binding, IdentifierVerifier $verifier): bool
    {
        $own = self::identifierOf($identity, $binding->type, $verifier);

        return $own !== null && hash_equals($binding->identifier, $own);
    }

    /**
     * The identity, unless the guard requires the identifier verified and the
     * identity, able to report it, has not verified it.
     *
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @return (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity)|\SineMacula\Laravel\Authentication\Events\Enums\FailureReason
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    private static function verified(JwtGuard $guard, Identity&Model $identity, string $type, Container $container): FailureReason|(Identity&Model)
    {
        if (!$identity instanceof HasVerifiableIdentifiers) {
            return $identity;
        }

        return $container->make(AudiencePolicy::class)->admitIdentifier($guard->getName(), $identity, $type) ?? $identity;
    }
}
