<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Verification;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\IdentifierVerified;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalisers;
use SineMacula\Laravel\Authentication\Identifiers\IdentifierType;
use SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification;

/**
 * Records that an identity has proven an identifier of a type, once a proof (a
 * signed link today, a one-time code later) has been checked.
 *
 * The proven identifier must be the identity's current one: both are compared
 * in their canonical form, through the type's normaliser when one is
 * registered, so a proof for an old address can never verify a new one. The
 * record itself is conditional on the identifier as it was read (see
 * `HasVerifiableIdentifiers::markIdentifierAsVerified()`), so an address
 * changed while the proof was checked is not verified either.
 *
 * Verifying never signs anyone in: it binds no guard, issues no token and
 * creates no device. `IdentifierVerified` is dispatched only by the call that
 * recorded the verification, once the record is committed on the identity's
 * connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class IdentifierVerifier
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Authentication\Identifiers\IdentifierNormalisers  $normalisers
     */
    public function __construct(

        /** Container the event dispatcher and transactions manager are resolved from when needed. */
        private Container $container,

        /** Normalisers that give identifiers their canonical form. */
        private IdentifierNormalisers $normalisers,
    ) {}

    /**
     * Verify the identity's identifier of the type, proven as `$identifier`.
     *
     * @param  string  $guard
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  string  $identifier
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return \SineMacula\Laravel\Authentication\Verification\Enums\IdentifierVerification
     *
     * @throws \InvalidArgumentException
     * @throws \LogicException
     */
    public function verify(string $guard, Identity $identity, string $type, #[\SensitiveParameter] string $identifier, ?ClientContext $client = null): IdentifierVerification
    {
        $verifiable = self::verifiable($identity);
        $current    = $this->current($verifiable, IdentifierType::assertValid($type));

        if ($current === null || !$this->isSameIdentifier($type, $current, $identifier)) {
            return IdentifierVerification::MISMATCH;
        }

        if ($verifiable->markIdentifierAsVerified($type, $current)) {

            $this->dispatchAfterCommit($identity, new IdentifierVerified(new EventContext($guard, $client ?? $this->servedClient(), $identity), $type));

            return IdentifierVerification::VERIFIED;
        }

        return $this->isAlreadyVerified($verifiable, $type, $current) ? IdentifierVerification::ALREADY_VERIFIED : IdentifierVerification::MISMATCH;
    }

    /**
     * The identifier in its canonical form: as the type's normaliser returns it
     * when one is registered (`null` when it rejects the value), otherwise as
     * given.
     *
     * @param  string  $type
     * @param  string  $identifier
     * @return ?string
     *
     * @throws \InvalidArgumentException
     */
    public function canonical(string $type, #[\SensitiveParameter] string $identifier): ?string
    {
        return $this->normalisers->has($type) ? $this->normalisers->get($type)->normalise($identifier) : $identifier;
    }

    /**
     * The identity as one whose identifiers can be verified.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @return \SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers&\SineMacula\Laravel\Authentication\Contracts\Identity
     *
     * @throws \LogicException
     */
    public static function verifiable(Identity $identity): HasVerifiableIdentifiers&Identity
    {
        if (!$identity instanceof HasVerifiableIdentifiers) {
            throw new \LogicException(sprintf('%s cannot verify identifiers: it does not implement %s.', $identity::class, HasVerifiableIdentifiers::class));
        }

        return $identity;
    }

    /**
     * The identity's current identifier of the type, read on the write
     * connection.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @return ?string
     */
    private function current(HasVerifiableIdentifiers&Identity $identity, string $type): ?string
    {
        return WriteConnection::during($identity, static fn (): ?string => $identity->getIdentifierForVerification($type));
    }

    /**
     * Whether two identifiers of the type are the same in their canonical form,
     * compared in constant time.
     *
     * @param  string  $type
     * @param  string  $current
     * @param  string  $proven
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function isSameIdentifier(string $type, #[\SensitiveParameter] string $current, #[\SensitiveParameter] string $proven): bool
    {
        $canonical = $this->canonical($type, $current);
        $candidate = $this->canonical($type, $proven);

        return $canonical !== null && $candidate !== null && hash_equals($canonical, $candidate);
    }

    /**
     * After a verification that recorded nothing, whether the identity, read
     * again from the write connection, still has the same identifier and has it
     * verified; otherwise the identifier changed meanwhile.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\HasVerifiableIdentifiers&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $type
     * @param  string  $identifier
     * @return bool
     */
    private function isAlreadyVerified(HasVerifiableIdentifiers&Identity $identity, string $type, #[\SensitiveParameter] string $identifier): bool
    {
        $fresh = $identity instanceof Model ? WriteConnection::during($identity, static fn (): ?Model => $identity->fresh()) : $identity;

        if (!$fresh instanceof HasVerifiableIdentifiers) {
            return false;
        }

        return WriteConnection::during($fresh, static fn (): bool => $fresh->getIdentifierForVerification($type) === $identifier && $fresh->hasVerifiedIdentifier($type));
    }

    /**
     * The client of the request being served, for a verification whose caller
     * named none.
     *
     * @return \SineMacula\Laravel\Authentication\Http\ClientContext
     */
    private function servedClient(): ClientContext
    {
        return ClientContext::fromRequest($this->container->make('request'));
    }

    /**
     * Dispatch the event once the identity's connection has committed, or at
     * once for an identity that is not an Eloquent model.
     *
     * @param  \SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Events\IdentifierVerified  $event
     * @return void
     */
    private function dispatchAfterCommit(Identity $identity, IdentifierVerified $event): void
    {
        $dispatch = fn (): mixed => $this->container->make(Dispatcher::class)->dispatch($event);

        if (!$identity instanceof Model) {

            $dispatch();

            return;
        }

        (new AfterCommit(fn (): mixed => $this->container->bound('db.transactions') ? $this->container->make('db.transactions') : null))->run($identity, $dispatch);
    }
}
