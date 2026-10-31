<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PasswordSet;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Writes a password the policy accepted: hashes it with Laravel's hasher, then,
 * in one transaction on the identity's connection, stores the hash and ends the
 * sessions the flow ends, and reports `PasswordSet` once that commits.
 *
 * An identity already stored gets one query-builder update of its password
 * column (and `updated_at`, when the model keeps timestamps) on its own row,
 * without its scopes: no other attribute is saved or discarded, and no model
 * event fires, so no observer can cancel the write or revoke again behind it. A
 * registration updates the row only while it has no password (`null` or empty),
 * in the same statement, so it can never replace one, which would be a change
 * that ends no session. An identity not stored yet, which only a registration
 * may set, is inserted with `save()`. The model is given the hash only once the
 * row has it.
 *
 * A change ends every session of the identity but the one it was made from,
 * when the caller keeps that device; a reset ends every session; a registration
 * ends none (see `SessionRevocations`). Ending them also cancels the identity's
 * pending identifier changes, whose links need no session. Whatever the flow,
 * every reset link and code still waiting for the identity's identifiers is
 * invalidated in the same transaction, and a change or a reset invalidates
 * their sign-in codes too (see `OutdatedProofs`): none can take the account
 * back once its owner has set a new password. When the devices live on another
 * connection, their revocation commits inside the identity's transaction, so a
 * failure after it leaves the devices revoked and the password as it was: more
 * is ended, never less.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class PasswordWriter
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Runtime\GuardContext  $context
     * @param  \SineMacula\Laravel\Authentication\Sessions\SessionRevocations  $revocations
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The context of the guard the change is made through, whose dispatcher reports it. */
        private GuardContext $context,

        /** Ends the sessions the flow ends. */
        private SessionRevocations $revocations,

        /** Container the hasher and the transactions manager are resolved from. */
        private Container $container,
    ) {}

    /**
     * Hash the password, store it, invalidate the proofs it outdates and end
     * the sessions the flow ends, cancelling the identity's pending identifier
     * changes with them, in one transaction, and report it once committed;
     * returns how many devices the flow revoked.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $password
     * @param  \SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow  $flow
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $except
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidDeviceModelConfigurationException
     * @throws \Throwable
     *
     * @imperative
     */
    public function write(Identity&Model $identity, #[\SensitiveParameter] string $password, PasswordFlow $flow, ?Device $except = null, ?ClientContext $client = null): int
    {
        // `#[\SensitiveParameter]` does not cover what a closure captures,
        // which a dump of the trace shows.
        $hash      = new \SensitiveParameterValue($this->container->make(Hasher::class)->make($password));
        $container = $this->container;
        $client ??= $this->context->client();
        $events = $this->context->events();

        return $identity->getConnection()->transaction(function () use ($identity, $hash, $flow, $except, $container, $client, $events): int {

            $this->store($identity, $hash->getValue(), $flow);

            (new OutdatedProofs($container))->invalidate($identity, $flow);

            $context = new EventContext($this->context->name(), $client, $identity, device: $except);

            $revoked = match ($flow) {
                PasswordFlow::CHANGE       => $this->revocations->passwordChanged($identity, $except),
                PasswordFlow::RESET        => $this->revocations->passwordReset($identity),
                PasswordFlow::REGISTRATION => 0,
            };

            (new AfterCommit(static fn (): mixed => $container->bound('db.transactions') ? $container->make('db.transactions') : null))
                ->run($identity, static fn () => $events->dispatch(new PasswordSet($context, $flow)));

            return $revoked;
        });
    }

    /**
     * Store the hash on the identity's row, or insert the identity when it is
     * not stored yet, and give the model the hash. A registration stores it
     * only on a row that has no password yet.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $hash
     * @param  \SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow  $flow
     * @return void
     *
     * @throws \LogicException
     */
    private function store(Identity&Model $identity, #[\SensitiveParameter] string $hash, PasswordFlow $flow): void
    {
        $column = $identity->getAuthPasswordName();

        if (!$identity->exists) {

            if (!$identity->forceFill([$column => $hash])->save()) {
                throw new \LogicException(sprintf('%s was not saved: a model event cancelled the registration, so no password was set.', $identity::class));
            }

            return;
        }

        $values  = [$column => $hash];
        $updated = $identity->usesTimestamps() ? $identity->getUpdatedAtColumn() : null;

        if ($updated !== null) {
            $values[$updated] = $identity->fromDateTime($identity->freshTimestamp());
        }

        $row          = $identity->newQueryWithoutScopes()->whereKey($identity->getKey());
        $registration = $flow === PasswordFlow::REGISTRATION;

        if ($registration) {
            $row->where(static fn (Builder $query): Builder => $query->whereNull($column)->orWhere($column, ''));
        }

        if ($row->toBase()->update($values) !== 1) {

            $message = $registration
                ? '%s %s already has a password, or is no longer stored: a registration sets only a first password.'
                : '%s %s is no longer stored, so no password was set.';

            throw new \LogicException(sprintf($message, $identity::class, IdentifierCoercion::stringify($identity->getKey())));
        }

        $identity->forceFill($values)->syncOriginalAttributes(array_keys($values));
    }
}
