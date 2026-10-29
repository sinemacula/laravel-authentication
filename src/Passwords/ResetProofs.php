<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Guards\JwtGuards;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalisers;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;

/**
 * The password reset links and codes a new password outdates, so a change or a
 * reset of the password can invalidate them in its own transaction: a reset
 * link or code someone else obtained before (a forwarded mail, a mailbox read
 * while it was compromised) then cannot take the account back once its owner
 * has recovered it.
 *
 * Outdated are the reset links and codes, through every `jwt` guard whose
 * provider can return the identity (see `JwtGuards::namesFor()`), of each
 * identifier the identity holds, in canonical form (see `ResetRecipient`), of a
 * type a reset can be bound to: a guard's password identifier, for links, and
 * any type with a registered normaliser, for codes. The identifiers are read
 * from the identity's row as it is stored, on the write connection inside the
 * transaction, never from the caller's model, which may have loaded only some
 * columns or be older than the row: a reset finds the identity by its row, so
 * an identifier left out would leave its links working. A type the row cannot
 * report at all (its `HasVerifiableIdentifiers` throws a `LogicException`, as
 * `ProvidesIdentifierVerification` does for a column the table does not have)
 * has nothing to outdate: a reset of it fails the same way before its proof is
 * checked. Misconfiguration (an `InvalidArgumentException`, a normaliser that
 * cannot be built, say) still fails closed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ResetProofs
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** Container the configuration, normalisers, verifier and engine are resolved from. */
        private Container $container,
    ) {}

    /**
     * Invalidate every reset link and code the identity's new password
     * outdates, in one statement on the codes' connection, once its stored row
     * is read; returns how many there were.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     *
     * @imperative
     */
    public function invalidate(Identity&Model $identity): int
    {
        $stored   = $identity->fresh() ?? $identity;
        $guards   = JwtGuards::namesFor($stored, $this->container->make(Repository::class));
        $verifier = $this->container->make(IdentifierVerifier::class);
        $bindings = [];

        foreach ($this->types($guards) as $type) {

            $identifier = self::identifierOf($stored, $type, $verifier);

            if ($identifier === null) {
                continue;
            }

            foreach ($guards as $guard) {
                $bindings[] = CodeBinding::passwordReset($guard, $type, $identifier);
                $bindings[] = CodeBinding::passwordResetLink($guard, $type, $identifier);
            }
        }

        return $this->container->make(OneTimeCodes::class)->invalidate($bindings);
    }

    /**
     * The identifier types a reset can be bound to: every type with a
     * registered normaliser, and each guard's password identifier. A type may
     * be named twice, which binds nothing more.
     *
     * @param  list<string>  $guards
     * @return list<string>
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     */
    private function types(array $guards): array
    {
        $sign = $this->container->make(PasswordSignIn::class);

        return [
            ...$this->container->make(IdentifierNormalisers::class)->types(),
            ...array_map(static fn (string $guard): string => $sign->identifierType($guard), $guards),
        ];
    }

    /**
     * The identity's identifier of the type in canonical form, or `null` when
     * it has none or cannot report one of the type.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  \SineMacula\Laravel\Authentication\Verification\IdentifierVerifier  $verifier
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    private static function identifierOf(Identity&Model $identity, string $type, IdentifierVerifier $verifier): ?string
    {
        try {
            return ResetRecipient::identifierOf($identity, $type, $verifier);
        } catch (\InvalidArgumentException $exception) {
            throw $exception;
        } catch (\LogicException) {
            return null;
        }
    }
}
