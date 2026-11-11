<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use Illuminate\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;
use SineMacula\Laravel\Authentication\Config\JwtGuards;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalizers;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Sessions\Methods\PasswordSignIn;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;

/**
 * The proofs a new password outdates, so setting it can invalidate them in its
 * own transaction.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OutdatedProofs
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
     * Invalidate every proof the identity's new password, set in the flow,
     * outdates.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow  $flow
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     *
     * @imperative
     */
    public function invalidate(Identity&Model $identity, PasswordFlow $flow): void
    {
        $stored   = $identity->fresh() ?? $identity;
        $guards   = JwtGuards::namesFor($stored, $this->container->make(Repository::class));
        $verifier = $this->container->make(IdentifierVerifier::class);
        $ends     = $flow !== PasswordFlow::REGISTRATION;
        $bindings = [];

        foreach ($this->types($guards) as $type) {

            $identifier = self::identifierOf($stored, $type, $verifier);

            if ($identifier === null) {
                continue;
            }

            foreach ($guards as $guard) {
                $bindings[] = CodeBinding::passwordReset($guard, $type, $identifier);
                $bindings[] = CodeBinding::passwordResetLink($guard, $type, $identifier);

                if (!$ends) {
                    continue;
                }

                $bindings[] = CodeBinding::signIn($guard, $type, $identifier);
            }
        }

        $this->container->make(OneTimeCodes::class)->invalidate($bindings);
    }

    /**
     * The identifier types a proof can be bound to: every type with a
     * registered normaliser, and each guard's password identifier.
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
            ...$this->container->make(IdentifierNormalizers::class)->types(),
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
