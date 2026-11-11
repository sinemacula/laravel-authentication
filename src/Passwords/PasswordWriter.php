<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Contracts\Session;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\Enums\RevocationReason;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PasswordSet;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;
use SineMacula\Laravel\Authentication\Runtime\GuardContext;
use SineMacula\Laravel\Authentication\Sessions\SessionRevocations;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;

/**
 * Writes a password the policy accepted and ends the sessions its flow ends, in
 * one transaction.
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
     * Hash and store the password, invalidate the proofs it outdates and end
     * the flow's sessions; returns how many were revoked.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $password
     * @param  \SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow  $flow
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Session  $except
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Exceptions\InvalidSessionModelConfigurationException
     * @throws \Throwable
     *
     * @imperative
     */
    public function write(Identity&Model $identity, #[\SensitiveParameter] string $password, PasswordFlow $flow, ClientContext $client, ?Session $except = null): int
    {
        // `#[\SensitiveParameter]` does not cover what a closure captures.
        $hash      = new \SensitiveParameterValue($this->container->make(Hasher::class)->make($password));
        $container = $this->container;

        return $identity->getConnection()->transaction(function () use ($identity, $hash, $flow, $except, $container, $client): int {

            $this->store($identity, $hash->getValue(), $flow);

            (new OutdatedProofs($container))->invalidate($identity, $flow);

            $event = new PasswordSet(new EventContext($this->context->name(), $client, $identity, session: $except), $flow);

            $revoked = match ($flow) {
                PasswordFlow::CHANGE        => $this->revocations->revokeSessions($identity, RevocationReason::PASSWORD_CHANGED, $except, client: $client),
                PasswordFlow::ESTABLISHMENT => $this->revocations->revokeSessions($identity, RevocationReason::PASSWORD_ESTABLISHED, $except, client: $client),
                PasswordFlow::RESET         => $this->revocations->revokeSessions($identity, RevocationReason::PASSWORD_RESET, client: $client),
                PasswordFlow::REGISTRATION  => 0,
            };

            (new AfterCommit(static fn (): mixed => $container->bound('db.transactions') ? $container->make('db.transactions') : null))
                ->run($identity, fn () => $this->context->dispatch($event));

            return $revoked;
        });
    }

    /**
     * Store the hash on the identity's row, or insert the identity when it is
     * not stored yet.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $hash
     * @param  \SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow  $flow
     * @return void
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Authentication\Passwords\PasswordAlreadySet
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

        $row = $identity->newQueryWithoutScopes()->whereKey($identity->getKey());

        if (in_array($flow, [PasswordFlow::REGISTRATION, PasswordFlow::ESTABLISHMENT], true)) {
            $row->where(static fn (Builder $query): Builder => $query->whereNull($column)->orWhere($column, ''));
        }

        if ($row->toBase()->update($values) !== 1) {
            throw self::unwritten($identity, $flow);
        }

        $identity->forceFill($values)->syncOriginalAttributes(array_keys($values));
    }

    /**
     * Why the update of a stored identity's password wrote no row.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  \SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow  $flow
     * @return \LogicException|\SineMacula\Laravel\Authentication\Passwords\PasswordAlreadySet
     */
    private static function unwritten(Identity&Model $identity, PasswordFlow $flow): \LogicException|PasswordAlreadySet
    {
        if ($flow === PasswordFlow::ESTABLISHMENT) {
            return new PasswordAlreadySet;
        }

        $message = $flow === PasswordFlow::REGISTRATION
            ? '%s %s already has a password, or is no longer stored: a registration sets only a first password.'
            : '%s %s is no longer stored, so no password was set.';

        return new \LogicException(sprintf($message, $identity::class, IdentifierCoercion::stringify($identity->getKey())));
    }
}
