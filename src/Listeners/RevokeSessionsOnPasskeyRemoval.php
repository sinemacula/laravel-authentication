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
 * Optional listener that ends every session of an identity that removed a
 * passkey, with reason `factor_removed`.
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
     * The identity the type and identifier name, read on the write connection
     * without global scopes, or `null` for none.
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
        $query = WriteConnection::query($model->newQueryWithoutScopes())->where($model->getAuthIdentifierName(), $id);

        /** @var (\Illuminate\Database\Eloquent\Model&\SineMacula\Laravel\Authentication\Contracts\Identity)|null */
        return WriteConnection::during($model, static fn (): ?Model => $query->first());
    }
}
