<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Listeners;

use Illuminate\Container\Container;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\Relation;
use SineMacula\Laravel\Authentication\Contracts\Identity;
use SineMacula\Laravel\Authentication\Database\WriteConnection;
use SineMacula\Laravel\Authentication\Events\PasskeyRemoved;

/**
 * Optional listener: ends every session of an identity that removed a passkey,
 * with reason `factor_removed`, through the session service of the guard the
 * passkey was removed through. `PasskeyRemoved` is dispatched only once the
 * removal is committed, so a removal that is rolled back revokes nothing.
 * Registering it is the opt-in:
 *
 * `Event::listen(PasskeyRemoved::class, RevokeSessionsOnPasskeyRemoval::class);`
 *
 * Every session is revoked, the one the passkey was removed from included; an
 * application that keeps that session signed in calls
 * `Auth::sessions()->credentialRemoved($identity, Auth::session())` itself
 * instead of registering the listener. A passkey the factor package associated
 * as a factor has its removal judged by the factor package, which calls
 * `factorRemoved()` itself; registered alongside it, the listener still ends
 * every session on any passkey's removal.
 *
 * The event names the identity by its type and identifier only, so the identity
 * is loaded again by them, on the write connection and with none of the model's
 * global scopes: a passkey only ever belongs to an Eloquent identity, and an
 * identity a scope hides (soft-deleted, or outside the tenant or application a
 * request is scoped to) must still lose the sessions it signed in with, or they
 * would be live again once it is visible. Its sessions are ended only when the
 * type names an Eloquent identity model, through the morph map or directly, and
 * a row of it has the identifier; an event that names none, or an identity that
 * is gone, ends nothing. The session service comes from the application now
 * serving, not from the container that built the listener, which under Octane
 * is the application the worker booted rather than the request's sandbox.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class RevokeSessionsOnPasskeyRemoval
{
    /**
     * End the sessions of the identity that removed the passkey.
     *
     * @param  \SineMacula\Laravel\Authentication\Events\PasskeyRemoved  $event
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     * @throws \InvalidArgumentException
     * @throws \LogicException
     * @throws \Throwable
     */
    public function handle(PasskeyRemoved $event): void
    {
        $context  = $event->context;
        $identity = self::identityOf($context->identityType, $context->identityId);

        if ($identity === null) {
            return;
        }

        /** @var \SineMacula\Laravel\Authentication\AuthManager $auth */
        $auth = Container::getInstance()->make('auth');

        $auth->sessions($context->guard)->credentialRemoved($identity);
    }

    /**
     * The identity the type and identifier name, read by its key on the write
     * connection with none of the model's global scopes, or `null` when the
     * type names no Eloquent identity model or no row has the identifier.
     *
     * @param  ?string  $type
     * @param  ?string  $id
     * @return ?\SineMacula\Laravel\Authentication\Contracts\Identity
     */
    private static function identityOf(?string $type, ?string $id): ?Identity
    {
        $class = $type === null ? null : Relation::getMorphedModel($type) ?? $type;

        if ($id === null || $class === null || !is_subclass_of($class, Model::class) || !is_subclass_of($class, Identity::class)) {
            return null;
        }

        /** @var \Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity $model */
        $model = new $class;
        $query = WriteConnection::query($model->newQueryWithoutScopes())->whereKey($id);

        /** @var (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity)|null */
        return WriteConnection::during($model, static fn (): ?Model => $query->first());
    }
}
