<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Passwords;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Eloquent\Model;
use SineMacula\Laravel\Authentication\Contracts\Device;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\AfterCommit;
use SineMacula\Laravel\Authentication\Events\EventContext;
use SineMacula\Laravel\Authentication\Events\PasswordSet;
use SineMacula\Laravel\Authentication\Guards\JwtGuard;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Jwt\IdentifierCoercion;
use SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow;

/**
 * Writes a password the policy accepted: hashes it with Laravel's hasher, then,
 * in one transaction on the identity's connection, stores the hash and ends the
 * sessions the flow ends, and reports `PasswordSet` once that commits.
 *
 * An identity already stored gets one query-builder update of its password
 * column (and `updated_at`, when the model keeps timestamps) on its own row,
 * without its scopes: no other attribute is saved or discarded, and no model
 * event fires, so no observer can cancel the write or revoke again behind it.
 * An identity not stored yet, which only a registration may set, is inserted
 * with `save()`. The model is given the hash only once the row has it.
 *
 * A change ends every session of the identity but the one it was made from,
 * when the caller keeps that device; a reset ends every session; a registration
 * ends none (see `RevokesOnSecurityChanges`). When the devices live on another
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
     * @param  \SineMacula\Laravel\Authentication\Guards\JwtGuard  $guard
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The guard whose session service ends the sessions, and whose dispatcher reports the change. */
        private JwtGuard $guard,

        /** Container the hasher and the transactions manager are resolved from. */
        private Container $container,
    ) {}

    /**
     * Hash the password, store it and end the flow's sessions in one
     * transaction, and report it once committed; returns how many devices the
     * flow revoked.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $password
     * @param  \SineMacula\Laravel\Authentication\Passwords\Enums\PasswordFlow  $flow
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Device  $except
     * @param  ?\SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @return int
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \LogicException
     * @throws \Throwable
     *
     * @imperative
     */
    public function write(Identity&Model $identity, #[\SensitiveParameter] string $password, PasswordFlow $flow, ?Device $except = null, ?ClientContext $client = null): int
    {
        $hash      = $this->container->make(Hasher::class)->make($password);
        $container = $this->container;
        $client ??= ClientContext::fromRequest($this->guard->getRequest());
        $events = $this->guard->getDispatcher();

        return $identity->getConnection()->transaction(function () use ($identity, $hash, $flow, $except, $container, $client, $events): int {

            $this->store($identity, $hash);

            $context = new EventContext($this->guard->getName(), $client, $identity, device: $except);

            $sessions = $this->guard->sessions();
            $revoked  = match ($flow) {
                PasswordFlow::CHANGE       => $sessions->passwordChanged($identity, $except),
                PasswordFlow::RESET        => $sessions->passwordReset($identity),
                PasswordFlow::REGISTRATION => 0,
            };

            (new AfterCommit(static fn (): mixed => $container->bound('db.transactions') ? $container->make('db.transactions') : null))
                ->run($identity, static fn () => $events->dispatch(new PasswordSet($context, $flow)));

            return $revoked;
        });
    }

    /**
     * Store the hash on the identity's row, or insert the identity when it is
     * not stored yet, and give the model the hash.
     *
     * @param  \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity  $identity
     * @param  string  $hash
     * @return void
     *
     * @throws \LogicException
     */
    private function store(Identity&Model $identity, #[\SensitiveParameter] string $hash): void
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

        if ($identity->newQueryWithoutScopes()->whereKey($identity->getKey())->toBase()->update($values) !== 1) {
            throw new \LogicException(sprintf('%s %s is no longer stored, so no password was set.', $identity::class, IdentifierCoercion::stringify($identity->getKey())));
        }

        $identity->forceFill($values)->syncOriginalAttributes(array_keys($values));
    }
}
